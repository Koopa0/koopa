package notion

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/task"
	"github.com/koopa0/blog-backend/internal/webhook"
)

// --------------------------------------------------------------------------
// Helpers for building signed webhook payloads
// --------------------------------------------------------------------------

// signPayload creates a "sha256=<hex>" HMAC-SHA256 signature over payload.
func signPayload(t *testing.T, payload []byte, secret string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// webhookBody builds a JSON webhook payload. If timestamp is empty, uses now.
func webhookBody(pageID, dataSourceID, timestamp string) []byte { //nolint:unparam // test helper designed for reuse with varied pageIDs
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	p := WebhookPayload{
		Type:      "page.updated",
		Timestamp: timestamp,
		Data: WebhookData{
			Parent: WebhookParent{
				Type:         "database_id",
				DataSourceID: dataSourceID,
			},
		},
		Entity: Entity{
			ID:   pageID,
			Type: "page",
		},
	}
	b, err := json.Marshal(p)
	if err != nil {
		panic(fmt.Sprintf("webhookBody: %v", err))
	}
	return b
}

// newTestDedup returns a webhook.DeduplicationCache for tests.
func newTestDedup(t *testing.T) *webhook.DeduplicationCache {
	t.Helper()
	c := webhook.NewDeduplicationCache(10 * time.Minute)
	t.Cleanup(c.Stop)
	return c
}

// newHandlerWithNotionServer creates a Handler that talks to srv for Notion API calls.
// dataSourceID→role is pre-seeded into the cache to avoid DB lookups.
func newHandlerWithNotionServer(t *testing.T, webhookSecret, dataSourceID, role string, srv *httptest.Server) *Handler {
	t.Helper()

	cache := newTestSourceCache(t)
	if dataSourceID != "" {
		seedCache(t, cache, dataSourceID, role)
	}

	h := &Handler{
		client:        newTestClient(srv),
		sourceCache:   cache,
		projects:      &mockProjectWriter{},
		goals:         &mockGoalWriter{},
		tasks:         &mockTaskWriter{},
		jobs:          &mockJobSubmitter{},
		webhookSecret: webhookSecret,
		logger:        slog.Default(),
	}
	return h
}

// seedCache sets a key in a ristretto cache and spins until the item is
// confirmed retrievable. Ristretto processes sets asynchronously;
// Wait() flushes the buffer but in rare cases the TinyLFU admission policy
// may delay visibility. A brief poll avoids races in tests.
func seedCache(t *testing.T, cache *ristretto.Cache[string, string], key, value string) {
	t.Helper()
	for i := range 50 {
		cache.SetWithTTL(key, value, 1, sourceCacheTTL)
		cache.Wait()
		if _, ok := cache.Get(key); ok {
			return
		}
		_ = i
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("seedCache: key %q never became visible in ristretto after 50 attempts", key)
}

// okNotionServer returns a test server that responds with a valid page JSON.
func okNotionServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := notionPageJSON(validPageIDForTest, false, false, map[string]string{
			"Name":   "Test Page",
			"Status": "Doing",
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// --------------------------------------------------------------------------
// Webhook — verification handshake
// --------------------------------------------------------------------------

func TestWebhook_VerificationHandshake(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		webhookSecret string
		body          string
		extraHeader   func(req *http.Request)
		wantCode      int
	}{
		{
			name:          "handshake accepted when secret is empty",
			webhookSecret: "",
			body:          `{"verification_token":"tok_abc123"}`,
			wantCode:      http.StatusOK,
		},
		{
			name:          "handshake rejected when secret is set (HMAC checked first)",
			webhookSecret: "super-secret",
			body:          `{"verification_token":"tok_abc123"}`,
			extraHeader: func(req *http.Request) {
				req.Header.Set("X-Notion-Signature", "sha256="+strings.Repeat("a", 64))
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name:          "non-handshake body without secret returns 501",
			webhookSecret: "",
			body:          `{"type":"page.updated"}`,
			wantCode:      http.StatusNotImplemented,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := okNotionServer(t)
			h := newHandlerWithNotionServer(t, tt.webhookSecret, "", "", srv)

			req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.extraHeader != nil {
				tt.extraHeader(req)
			}
			w := httptest.NewRecorder()

			h.Webhook(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("Webhook() handshake: status = %d, want %d\nbody: %s", w.Code, tt.wantCode, w.Body.String())
			}
		})
	}
}

// --------------------------------------------------------------------------
// Webhook — HMAC signature validation
// --------------------------------------------------------------------------

func TestWebhook_SignatureValidation(t *testing.T) {
	t.Parallel()

	const secret = "webhook-secret-xyz"
	const dataSourceID = "ds-sig-test"

	payload := webhookBody(validPageIDForTest, dataSourceID, "")
	goodSig := signPayload(t, payload, secret)

	tests := []struct {
		name     string
		sig      string
		wantCode int
	}{
		{
			name:     "valid signature passes",
			sig:      goodSig,
			wantCode: http.StatusOK,
		},
		{
			name:     "wrong signature returns 401",
			sig:      "sha256=" + strings.Repeat("a", 64),
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "missing sha256= prefix returns 401",
			sig:      "invalid-sig",
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "empty signature returns 401",
			sig:      "",
			wantCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := okNotionServer(t)
			h := newHandlerWithNotionServer(t, secret, dataSourceID, RoleProjects, srv)

			req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion", strings.NewReader(string(payload)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Notion-Signature", tt.sig)
			w := httptest.NewRecorder()

			h.Webhook(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("Webhook() sig=%q: status = %d, want %d", tt.sig, w.Code, tt.wantCode)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Webhook — empty/stale timestamp rejected when dedup is enabled
// --------------------------------------------------------------------------

func TestWebhook_TimestampValidation(t *testing.T) {
	t.Parallel()

	const secret = "ts-test-secret"
	const dataSourceID = "ds-ts-test"

	makeSignedReq := func(t *testing.T, body []byte) *http.Request {
		t.Helper()
		sig := signPayload(t, body, secret)
		req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion", strings.NewReader(string(body)))
		req.Header.Set("X-Notion-Signature", sig)
		return req
	}

	t.Run("missing timestamp returns 400 when dedup enabled", func(t *testing.T) {
		t.Parallel()

		srv := okNotionServer(t)
		h := newHandlerWithNotionServer(t, secret, dataSourceID, RoleProjects, srv)
		h.dedup = newTestDedup(t)

		p := WebhookPayload{
			Type:      "page.updated",
			Timestamp: "",
			Data:      WebhookData{Parent: WebhookParent{DataSourceID: dataSourceID}},
			Entity:    Entity{ID: validPageIDForTest, Type: "page"},
		}
		body, _ := json.Marshal(p)
		w := httptest.NewRecorder()
		h.Webhook(w, makeSignedReq(t, body))

		if w.Code != http.StatusBadRequest {
			t.Errorf("Webhook() missing timestamp: status = %d, want 400", w.Code)
		}
	})

	t.Run("expired timestamp returns 400 when dedup enabled", func(t *testing.T) {
		t.Parallel()

		srv := okNotionServer(t)
		h := newHandlerWithNotionServer(t, secret, dataSourceID, RoleProjects, srv)
		h.dedup = newTestDedup(t)

		oldTS := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
		body := webhookBody(validPageIDForTest, dataSourceID, oldTS)
		w := httptest.NewRecorder()
		h.Webhook(w, makeSignedReq(t, body))

		if w.Code != http.StatusBadRequest {
			t.Errorf("Webhook() expired timestamp: status = %d, want 400", w.Code)
		}
	})
}

// --------------------------------------------------------------------------
// Webhook — dedup: replayed event returns 200 without re-processing
// --------------------------------------------------------------------------

func TestWebhook_Dedup(t *testing.T) {
	t.Parallel()

	const secret = "dedup-secret"
	const dataSourceID = "ds-dedup"

	upsertCount := 0

	srv := okNotionServer(t)
	cache := newTestSourceCache(t)
	seedCache(t, cache, dataSourceID, RoleProjects)

	h := &Handler{
		client:      newTestClient(srv),
		sourceCache: cache,
		projects: &mockProjectWriter{
			upsertFn: func(_ context.Context, _ *project.UpsertByNotionParams) (*project.Project, error) {
				upsertCount++
				return &project.Project{ID: uuid.New()}, nil
			},
		},
		goals:         &mockGoalWriter{},
		tasks:         &mockTaskWriter{},
		jobs:          &mockJobSubmitter{},
		webhookSecret: secret,
		logger:        slog.Default(),
		dedup:         newTestDedup(t),
	}

	// Use a fixed timestamp so both requests produce the same dedup key
	ts := time.Now().UTC().Format(time.RFC3339)
	body := webhookBody(validPageIDForTest, dataSourceID, ts)
	sig := signPayload(t, body, secret)

	sendReq := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion",
			strings.NewReader(string(body)))
		req.Header.Set("X-Notion-Signature", sig)
		w := httptest.NewRecorder()
		h.Webhook(w, req)
		return w.Code
	}

	if code := sendReq(); code != http.StatusOK {
		t.Fatalf("Webhook() first request: status = %d, want 200", code)
	}
	firstUpsertCount := upsertCount

	if code := sendReq(); code != http.StatusOK {
		t.Fatalf("Webhook() replayed request: status = %d, want 200", code)
	}

	// upsert count must not increase on replay
	if upsertCount != firstUpsertCount {
		t.Errorf("Webhook() dedup: upsertCount = %d after replay, want %d (no increase)", upsertCount, firstUpsertCount)
	}
}

// --------------------------------------------------------------------------
// Webhook — routing: known roles dispatch to correct sync, unknown returns 200
// --------------------------------------------------------------------------

func TestWebhook_Routing(t *testing.T) {
	t.Parallel()

	const secret = "routing-secret"

	tests := []struct {
		name         string
		role         string
		dataSourceID string
		notionProps  map[string]string
		wantCode     int
	}{
		{
			name:         "projects role routes correctly",
			role:         RoleProjects,
			dataSourceID: "ds-projects",
			notionProps:  map[string]string{"Name": "Project A", "Status": "Doing"},
			wantCode:     http.StatusOK,
		},
		{
			name:         "goals role routes correctly",
			role:         RoleGoals,
			dataSourceID: "ds-goals",
			notionProps:  map[string]string{"Name": "Goal A", "Status": "In Progress"},
			wantCode:     http.StatusOK,
		},
		{
			name:         "tasks role routes correctly",
			role:         RoleTasks,
			dataSourceID: "ds-tasks",
			notionProps:  map[string]string{"Task Name": "Task A", "Status": "To Do"},
			wantCode:     http.StatusOK,
		},
		{
			name:         "unknown role returns 200 best-effort",
			role:         "",
			dataSourceID: "ds-unknown",
			notionProps:  map[string]string{"Name": "Unknown", "Status": "Doing"},
			wantCode:     http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := notionPageJSON(validPageIDForTest, false, false, tt.notionProps)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, resp)
			}))
			t.Cleanup(srv.Close)

			h := newHandlerWithNotionServer(t, secret, tt.dataSourceID, tt.role, srv)

			ts := time.Now().UTC().Format(time.RFC3339)
			body := webhookBody(validPageIDForTest, tt.dataSourceID, ts)
			sig := signPayload(t, body, secret)

			req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion",
				strings.NewReader(string(body)))
			req.Header.Set("X-Notion-Signature", sig)
			w := httptest.NewRecorder()
			h.Webhook(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("Webhook() role=%q: status = %d, want %d", tt.role, w.Code, tt.wantCode)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Webhook — sync errors still return 200 (best-effort, Notion must not retry)
// --------------------------------------------------------------------------

func TestWebhook_SyncErrorStillReturns200(t *testing.T) {
	t.Parallel()

	const secret = "err-secret"
	const dataSourceID = "ds-err"

	// Notion API always returns error
	notionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, `{"message":"internal error"}`)
	}))
	t.Cleanup(notionSrv.Close)

	h := newHandlerWithNotionServer(t, secret, dataSourceID, RoleProjects, notionSrv)

	ts := time.Now().UTC().Format(time.RFC3339)
	body := webhookBody(validPageIDForTest, dataSourceID, ts)
	sig := signPayload(t, body, secret)

	req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion",
		strings.NewReader(string(body)))
	req.Header.Set("X-Notion-Signature", sig)
	w := httptest.NewRecorder()
	h.Webhook(w, req)

	// Sync errors must not cause Notion to receive a non-200
	if w.Code != http.StatusOK {
		t.Errorf("Webhook() sync error: status = %d, want 200", w.Code)
	}
}

// --------------------------------------------------------------------------
// Webhook — invalid JSON body returns 400
// --------------------------------------------------------------------------

func TestWebhook_InvalidJSONBody(t *testing.T) {
	t.Parallel()

	const secret = "json-secret"

	badBody := []byte(`{not valid json`)
	sig := signPayload(t, badBody, secret)

	srv := okNotionServer(t)
	h := newHandlerWithNotionServer(t, secret, "", "", srv)

	req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion",
		strings.NewReader(string(badBody)))
	req.Header.Set("X-Notion-Signature", sig)
	w := httptest.NewRecorder()
	h.Webhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Webhook() invalid JSON: status = %d, want 400", w.Code)
	}
}

// Ensure the imported packages are used (compile guard).
var _ = goal.StatusDone
var _ = project.StatusCompleted
var _ = task.StatusDone
var _ = uuid.Nil
