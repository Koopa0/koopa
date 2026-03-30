package notion

import (
	"bytes"
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
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/webhook"
)

// ============================================================================
// Helpers
// ============================================================================

// newTestCache returns a minimal Ristretto cache for use in tests.
func newTestCache(t *testing.T) *ristretto.Cache[string, string] {
	t.Helper()
	c, err := ristretto.NewCache[string, string](&ristretto.Config[string, string]{
		NumCounters: 1e3,
		MaxCost:     1 << 20,
		BufferItems: 64,
	})
	if err != nil {
		t.Fatalf("newTestCache: creating ristretto cache: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// discardLogger returns a slog.Logger that drops all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// newTestWebhookHandler returns a Handler with no store, no client, and no
// syncer wired. Suitable only for testing Webhook request validation paths
// (HMAC, replay, body size, handshake) that do not reach the store.
func newTestWebhookHandler(t *testing.T, secret string, dedup *webhook.DeduplicationCache) *Handler {
	t.Helper()
	cache := newTestCache(t)
	h := NewHandler(
		nil, // client — not reached in validation tests
		nil, // store  — not reached in validation tests
		cache,
		nil, // exec.Runner — not reached
		secret,
		discardLogger(),
	)
	if dedup != nil {
		h.dedup = dedup
		// Caller is responsible for dedup.Stop via t.Cleanup.
	}
	return h
}

// validHMACSignature returns a "sha256=<hex>" signature for body using secret.
func validHMACSignature(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// webhookPayloadJSON builds a minimal valid WebhookPayload JSON with a fresh timestamp.
func webhookPayloadJSON(entityID, dataSourceID string) []byte {
	ts := time.Now().UTC().Format(time.RFC3339)
	payload := fmt.Sprintf(
		`{"type":"page.updated","timestamp":%q,"entity":{"id":%q,"type":"page"},"data":{"parent":{"type":"database_id","data_source_id":%q}}}`,
		ts, entityID, dataSourceID,
	)
	return []byte(payload)
}

// newTestSourceHandler returns a SourceHandler with nil store, nil client, and
// nil sourceCache wired to a discard logger. Only call this for tests that
// exercise code paths that do NOT reach the store (UUID parsing, JSON decode
// validation, nil-client guard). Store-calling paths require integration tests.
func newTestSourceHandler(t *testing.T) *SourceHandler {
	t.Helper()
	cache := newTestCache(t)
	return NewSourceHandler(nil, nil, cache, discardLogger())
}

// ============================================================================
// Handler.Webhook — HMAC signature verification
// ============================================================================

// TestWebhook_HMACRejection tests all paths where the Webhook handler rejects
// a request before reaching the store. A valid-signature case that dispatches
// to the store requires an integration test (store is nil here and would panic).
func TestWebhook_HMACRejection(t *testing.T) {
	t.Parallel()

	const secret = "test-secret-abc"
	body := webhookPayloadJSON("page-1", "db-1")
	validSig := validHMACSignature(body, secret)

	tests := []struct {
		name       string
		body       []byte
		sig        string
		wantStatus int
	}{
		{
			name:       "missing signature header",
			body:       body,
			sig:        "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong prefix — no sha256= prefix",
			body:       body,
			sig:        hex.EncodeToString([]byte("notasig")),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "tampered body with original signature",
			body:       append([]byte(nil), append(body, []byte(" tampered")...)...),
			sig:        validSig,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "correct prefix but wrong hex digits",
			body:       body,
			sig:        "sha256=deadbeefdeadbeefdeadbeefdeadbeef",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "valid prefix but non-hex payload",
			body:       body,
			sig:        "sha256=notactuallyhex!!!",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "valid sig but wrong secret",
			body:       body,
			sig:        validHMACSignature(body, "different-secret"),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "sha256= prefix only, empty hex",
			body:       body,
			sig:        "sha256=",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// No dedup — these tests never pass signature check, so dedup
			// is irrelevant. nil dedup disables replay protection (fine here).
			h := newTestWebhookHandler(t, secret, nil)

			req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion", bytes.NewReader(tt.body))
			req.Header.Set("X-Notion-Signature", tt.sig)
			w := httptest.NewRecorder()

			h.Webhook(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Webhook(%q) status = %d, want %d (response: %s)",
					tt.name, w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

// ============================================================================
// Handler.Webhook — body size limit
// ============================================================================

func TestWebhook_OversizedBody(t *testing.T) {
	t.Parallel()

	const secret = "test-secret"
	// Build a body just over the 1 MB limit.
	oversized := bytes.Repeat([]byte("x"), (1<<20)+1)
	sig := validHMACSignature(oversized, secret)

	req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion", bytes.NewReader(oversized))
	req.Header.Set("X-Notion-Signature", sig)
	w := httptest.NewRecorder()

	h := newTestWebhookHandler(t, secret, nil)
	h.Webhook(w, req)

	// MaxBytesReader causes io.ReadAll to fail → 400.
	if w.Code != http.StatusBadRequest {
		t.Errorf("Webhook(oversized) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ============================================================================
// Handler.Webhook — malformed JSON body (valid signature, bad JSON)
// ============================================================================

func TestWebhook_MalformedJSON(t *testing.T) {
	t.Parallel()

	const secret = "test-secret"
	body := []byte(`{"type": "page.updated", "timestamp": `) // truncated JSON
	sig := validHMACSignature(body, secret)

	req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion", bytes.NewReader(body))
	req.Header.Set("X-Notion-Signature", sig)
	w := httptest.NewRecorder()

	h := newTestWebhookHandler(t, secret, nil)
	h.Webhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Webhook(malformed JSON) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ============================================================================
// Handler.Webhook — replay protection
// ============================================================================

// TestWebhook_ReplayProtection verifies that a duplicate delivery ID is silently
// accepted (200) rather than re-processed. The dedup cache is pre-seeded with the
// delivery key so neither request reaches the store — both are identified as replays.
//
// Testing the "first delivery accepted + second replay" flow end-to-end requires
// an integration test because the first delivery reaches the store via dispatchWebhookSync.
func TestWebhook_ReplayProtection(t *testing.T) {
	t.Parallel()

	const secret = "replay-secret"
	dedup := webhook.NewDeduplicationCache(10 * time.Minute)
	t.Cleanup(dedup.Stop)

	h := newTestWebhookHandler(t, secret, dedup)

	// Use a fixed timestamp so both requests produce the same dedup key.
	ts := time.Now().UTC().Format(time.RFC3339)
	body := []byte(fmt.Sprintf(
		`{"type":"page.updated","timestamp":%q,"entity":{"id":"entity-replay","type":"page"},"data":{"parent":{"type":"database_id","data_source_id":"ds-replay"}}}`,
		ts,
	))
	sig := validHMACSignature(body, secret)

	// Pre-seed the dedup cache with the delivery key that the handler would compute.
	// This simulates "this delivery was already processed" so BOTH requests below
	// are treated as replays — neither reaches the nil store.
	dedupKey := "entity-replay" + "|" + ts
	dedup.Seen(dedupKey) // marks key as seen; next Seen() call returns true

	sendRequest := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion", bytes.NewReader(body))
		req.Header.Set("X-Notion-Signature", sig)
		w := httptest.NewRecorder()
		h.Webhook(w, req)
		return w.Code
	}

	// Both requests are replays of the pre-seeded key.
	// The handler must return 200 (not 4xx) so Notion stops retrying.
	for i := range 2 {
		if code := sendRequest(); code != http.StatusOK {
			t.Errorf("Webhook(replay attempt %d) status = %d, want %d", i+1, code, http.StatusOK)
		}
	}
}

// ============================================================================
// Handler.Webhook — missing timestamp when dedup is active
// ============================================================================

func TestWebhook_MissingTimestamp(t *testing.T) {
	t.Parallel()

	const secret = "ts-secret"
	dedup := webhook.NewDeduplicationCache(10 * time.Minute)
	h := newTestWebhookHandler(t, secret, dedup)

	// Valid JSON but no "timestamp" field.
	body := []byte(`{"type":"page.updated","entity":{"id":"page-1","type":"page"},"data":{"parent":{"type":"database_id","data_source_id":"ds-1"}}}`)
	sig := validHMACSignature(body, secret)

	req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion", bytes.NewReader(body))
	req.Header.Set("X-Notion-Signature", sig)
	w := httptest.NewRecorder()

	h.Webhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Webhook(missing timestamp) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ============================================================================
// Handler.Webhook — verification handshake (webhookSecret == "")
// ============================================================================

func TestWebhook_VerificationHandshake(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "valid handshake probe",
			body:       `{"verification_token":"abc-token-123"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "empty verification_token",
			body:       `{"verification_token":""}`,
			wantStatus: http.StatusNotImplemented,
		},
		{
			name:       "missing verification_token field",
			body:       `{"type":"page.updated"}`,
			wantStatus: http.StatusNotImplemented,
		},
		{
			name:       "empty JSON object",
			body:       `{}`,
			wantStatus: http.StatusNotImplemented,
		},
		{
			name:       "malformed JSON",
			body:       `{not valid json`,
			wantStatus: http.StatusNotImplemented,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Secret is empty — triggers handshake path.
			h := newTestWebhookHandler(t, "", nil)

			req := httptest.NewRequest(http.MethodPost, "/api/webhook/notion", strings.NewReader(tt.body))
			w := httptest.NewRecorder()

			h.Webhook(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Webhook(handshake %q) status = %d, want %d", tt.name, w.Code, tt.wantStatus)
			}
		})
	}
}

// ============================================================================
// validateCreateSourceParams — pure validation function
// ============================================================================

func TestValidateCreateSourceParams(t *testing.T) {
	t.Parallel()

	roleProjects := RoleProjects
	roleBad := "hacker"

	tests := []struct {
		name    string
		params  CreateSourceParams
		wantMsg string // empty means valid
	}{
		{
			name: "valid minimal",
			params: CreateSourceParams{
				DatabaseID: "abc-database-id",
				Name:       "My Database",
			},
			wantMsg: "",
		},
		{
			name: "valid with all fields",
			params: CreateSourceParams{
				DatabaseID:   "abc-database-id",
				Name:         "My Database",
				SyncMode:     SyncModeFull,
				PollInterval: "15 minutes",
				PropertyMap:  json.RawMessage(`{"foo":"bar"}`),
				Role:         &roleProjects,
			},
			wantMsg: "",
		},
		{
			name:    "missing database_id",
			params:  CreateSourceParams{Name: "Test"},
			wantMsg: "database_id and name are required",
		},
		{
			name:    "missing name",
			params:  CreateSourceParams{DatabaseID: "some-db-id"},
			wantMsg: "database_id and name are required",
		},
		{
			name:    "both empty",
			params:  CreateSourceParams{},
			wantMsg: "database_id and name are required",
		},
		{
			name: "database_id exceeds 255 chars",
			params: CreateSourceParams{
				DatabaseID: strings.Repeat("x", 256),
				Name:       "OK",
			},
			wantMsg: "database_id exceeds 255 characters",
		},
		{
			name: "database_id exactly 255 chars — valid",
			params: CreateSourceParams{
				DatabaseID: strings.Repeat("x", 255),
				Name:       "OK",
			},
			wantMsg: "",
		},
		{
			name: "name exceeds 255 chars",
			params: CreateSourceParams{
				DatabaseID: "db-id",
				Name:       strings.Repeat("n", 256),
			},
			wantMsg: "name exceeds 255 characters",
		},
		{
			name: "description exceeds 1024 runes",
			params: CreateSourceParams{
				DatabaseID:  "db-id",
				Name:        "OK",
				Description: strings.Repeat("d", 1025),
			},
			wantMsg: "description exceeds 1024 characters",
		},
		{
			name: "description exactly 1024 runes — valid",
			params: CreateSourceParams{
				DatabaseID:  "db-id",
				Name:        "OK",
				Description: strings.Repeat("d", 1024),
			},
			wantMsg: "",
		},
		{
			name: "invalid role",
			params: CreateSourceParams{
				DatabaseID: "db-id",
				Name:       "OK",
				Role:       &roleBad,
			},
			wantMsg: "invalid role",
		},
		{
			name: "invalid sync_mode",
			params: CreateSourceParams{
				DatabaseID: "db-id",
				Name:       "OK",
				SyncMode:   "streaming",
			},
			wantMsg: "invalid sync_mode",
		},
		{
			name: "invalid poll_interval",
			params: CreateSourceParams{
				DatabaseID:   "db-id",
				Name:         "OK",
				PollInterval: "2 minutes",
			},
			wantMsg: "invalid poll_interval",
		},
		{
			name: "property_map exceeds 64 KB",
			params: CreateSourceParams{
				DatabaseID:  "db-id",
				Name:        "OK",
				PropertyMap: json.RawMessage(`{"k":"` + strings.Repeat("v", 64*1024) + `"}`),
			},
			wantMsg: "property_map exceeds 64 KB",
		},
		{
			name: "property_map is invalid JSON",
			params: CreateSourceParams{
				DatabaseID:  "db-id",
				Name:        "OK",
				PropertyMap: json.RawMessage(`{invalid json}`),
			},
			wantMsg: "property_map is not valid JSON",
		},
		{
			name: "sql injection in database_id field",
			params: CreateSourceParams{
				DatabaseID: "';DROP-TABLE-sources;--",
				Name:       "injection",
			},
			wantMsg: "", // validation does not restrict SQL chars; store uses parameterized queries
		},
		{
			name: "unicode name — valid",
			params: CreateSourceParams{
				DatabaseID: "db-id",
				Name:       "個人知識庫",
			},
			wantMsg: "",
		},
		{
			name: "description exactly 1024 unicode runes — valid",
			params: CreateSourceParams{
				DatabaseID:  "db-id",
				Name:        "OK",
				Description: strings.Repeat("字", 1024), // 1024 runes, each 3 bytes
			},
			wantMsg: "",
		},
		{
			name: "description 1025 unicode runes — invalid",
			params: CreateSourceParams{
				DatabaseID:  "db-id",
				Name:        "OK",
				Description: strings.Repeat("字", 1025),
			},
			wantMsg: "description exceeds 1024 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := tt.params // copy so defaults mutation does not affect other subtests
			got := validateCreateSourceParams(&p)
			if tt.wantMsg == "" {
				if got != "" {
					t.Errorf("validateCreateSourceParams() = %q, want empty (valid)", got)
				}
			} else {
				if !strings.Contains(got, tt.wantMsg) {
					t.Errorf("validateCreateSourceParams() = %q, want message containing %q", got, tt.wantMsg)
				}
			}
		})
	}
}

// TestValidateCreateSourceParams_DefaultsApplied verifies that the function
// fills in SyncMode and PollInterval when they are empty.
func TestValidateCreateSourceParams_DefaultsApplied(t *testing.T) {
	t.Parallel()

	p := CreateSourceParams{DatabaseID: "db-id", Name: "Test"}
	msg := validateCreateSourceParams(&p)
	if msg != "" {
		t.Fatalf("validateCreateSourceParams() unexpected error: %q", msg)
	}

	if diff := cmp.Diff(SyncModeFull, p.SyncMode); diff != "" {
		t.Errorf("SyncMode default mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("15 minutes", p.PollInterval); diff != "" {
		t.Errorf("PollInterval default mismatch (-want +got):\n%s", diff)
	}
	if p.PropertyMap == nil {
		t.Error("PropertyMap should default to {} but is nil")
	}
}

// ============================================================================
// validateUpdateSourceParams — pure validation function
// ============================================================================

func TestValidateUpdateSourceParams(t *testing.T) {
	t.Parallel()

	ptr := func(s string) *string { return &s }
	ptrBool := func(b bool) *bool { return &b }
	ptrRaw := func(s string) *json.RawMessage { r := json.RawMessage(s); return &r }

	tests := []struct {
		name    string
		params  UpdateSourceParams
		wantMsg string
	}{
		{
			name:    "empty params — all optional, valid",
			params:  UpdateSourceParams{},
			wantMsg: "",
		},
		{
			name:    "valid sync_mode full",
			params:  UpdateSourceParams{SyncMode: ptr(SyncModeFull)},
			wantMsg: "",
		},
		{
			name:    "valid sync_mode events",
			params:  UpdateSourceParams{SyncMode: ptr(SyncModeEvents)},
			wantMsg: "",
		},
		{
			name:    "invalid sync_mode",
			params:  UpdateSourceParams{SyncMode: ptr("streaming")},
			wantMsg: "invalid sync_mode",
		},
		{
			name:    "empty name — invalid",
			params:  UpdateSourceParams{Name: ptr("")},
			wantMsg: "name cannot be empty",
		},
		{
			name:    "name within 255 — valid",
			params:  UpdateSourceParams{Name: ptr(strings.Repeat("n", 255))},
			wantMsg: "",
		},
		{
			name:    "name exceeds 255 — invalid",
			params:  UpdateSourceParams{Name: ptr(strings.Repeat("n", 256))},
			wantMsg: "name exceeds 255 characters",
		},
		{
			name:    "invalid poll_interval",
			params:  UpdateSourceParams{PollInterval: ptr("every second")},
			wantMsg: "invalid poll_interval",
		},
		{
			name:    "valid poll_interval",
			params:  UpdateSourceParams{PollInterval: ptr("1 hour")},
			wantMsg: "",
		},
		{
			name:    "property_map exceeds 64 KB",
			params:  UpdateSourceParams{PropertyMap: ptrRaw(`{"k":"` + strings.Repeat("v", 64*1024) + `"}`)},
			wantMsg: "property_map exceeds 64 KB",
		},
		{
			name:    "property_map invalid JSON",
			params:  UpdateSourceParams{PropertyMap: ptrRaw(`{bad json}`)},
			wantMsg: "property_map is not valid JSON",
		},
		{
			name:    "valid property_map",
			params:  UpdateSourceParams{PropertyMap: ptrRaw(`{"custom_field":"value"}`)},
			wantMsg: "",
		},
		{
			name:    "enabled flag — valid (not validated, just stored)",
			params:  UpdateSourceParams{Enabled: ptrBool(false)},
			wantMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := validateUpdateSourceParams(&tt.params)
			if tt.wantMsg == "" {
				if got != "" {
					t.Errorf("validateUpdateSourceParams() = %q, want empty (valid)", got)
				}
			} else {
				if !strings.Contains(got, tt.wantMsg) {
					t.Errorf("validateUpdateSourceParams() = %q, want message containing %q", got, tt.wantMsg)
				}
			}
		})
	}
}

// ============================================================================
// SourceHandler.ByID — UUID path parameter validation
// ============================================================================

func TestSourceHandler_ByID_InvalidUUID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pathValue  string
		wantStatus int
	}{
		{
			name:       "not a UUID",
			pathValue:  "not-a-uuid",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty string",
			pathValue:  "",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "SQL injection",
			pathValue:  "1';DROP-TABLE-sources;--",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "path traversal attempt",
			pathValue:  "../etc/passwd",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "integer ID (wrong format)",
			pathValue:  "12345",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "null bytes (URL-encoded)",
			pathValue:  "abc%00def",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestSourceHandler(t)
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.SetPathValue("id", tt.pathValue)
			w := httptest.NewRecorder()

			h.ByID(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("ByID(%q) status = %d, want %d", tt.pathValue, w.Code, tt.wantStatus)
			}
		})
	}
}

// ============================================================================
// SourceHandler.Update — UUID validation + body validation
// ============================================================================

func TestSourceHandler_Update_InvalidUUID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pathID     string
		wantStatus int
	}{
		{name: "not a UUID", pathID: "abc", wantStatus: http.StatusBadRequest},
		{name: "empty", pathID: "", wantStatus: http.StatusBadRequest},
		{name: "SQL injection", pathID: "1';DROP-TABLE--", wantStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestSourceHandler(t)
			body := strings.NewReader(`{}`)
			req := httptest.NewRequest(http.MethodPut, "/api/admin/notion-sources/"+tt.pathID, body)
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()

			h.Update(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Update(id=%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
			}
		})
	}
}

func TestSourceHandler_Update_ValidationErrors(t *testing.T) {
	t.Parallel()

	validID := uuid.New().String()

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantMsg    string
	}{
		{
			name:       "malformed JSON body",
			body:       `{bad json`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid sync_mode",
			body:       `{"sync_mode":"streaming"}`,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "invalid sync_mode",
		},
		{
			name:       "empty name",
			body:       `{"name":""}`,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "name cannot be empty",
		},
		{
			name:       "invalid poll_interval",
			body:       `{"poll_interval":"every second"}`,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "invalid poll_interval",
		},
		// Valid property_map passes validation and reaches the store (nil → panic).
		// Covered by integration tests.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestSourceHandler(t)
			req := httptest.NewRequest(http.MethodPut, "/api/admin/notion-sources/"+validID, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", validID)
			w := httptest.NewRecorder()

			h.Update(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Update(body=%q) status = %d, want %d (response: %s)", tt.name, w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantMsg != "" {
				if !strings.Contains(w.Body.String(), tt.wantMsg) {
					t.Errorf("Update(body=%q) response = %s, want to contain %q", tt.name, w.Body.String(), tt.wantMsg)
				}
			}
		})
	}
}

// ============================================================================
// SourceHandler.Delete — UUID validation
// ============================================================================

func TestSourceHandler_Delete_InvalidUUID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pathID     string
		wantStatus int
	}{
		{name: "not a UUID", pathID: "abc", wantStatus: http.StatusBadRequest},
		{name: "empty", pathID: "", wantStatus: http.StatusBadRequest},
		{name: "SQL injection", pathID: "';DROP-TABLE-sources;--", wantStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestSourceHandler(t)
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()

			h.Delete(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Delete(id=%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
			}
		})
	}
}

// ============================================================================
// SourceHandler.Toggle — UUID validation
// ============================================================================

func TestSourceHandler_Toggle_InvalidUUID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pathID     string
		wantStatus int
	}{
		{name: "not a UUID", pathID: "xyz", wantStatus: http.StatusBadRequest},
		{name: "empty", pathID: "", wantStatus: http.StatusBadRequest},
		{name: "integer ID", pathID: "42", wantStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestSourceHandler(t)
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()

			h.Toggle(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Toggle(id=%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
			}
		})
	}
}

// ============================================================================
// SourceHandler.SetRole — UUID validation + role validation
// ============================================================================

func TestSourceHandler_SetRole_InvalidUUID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pathID     string
		wantStatus int
	}{
		{name: "not a UUID", pathID: "bad-id", wantStatus: http.StatusBadRequest},
		{name: "empty", pathID: "", wantStatus: http.StatusBadRequest},
		{name: "XSS attempt", pathID: "<script>alert(1)</script>", wantStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestSourceHandler(t)
			req := httptest.NewRequest(http.MethodPut, "/api/admin/notion-sources/x/role", strings.NewReader(`{"role":"projects"}`))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.pathID)
			w := httptest.NewRecorder()

			h.SetRole(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("SetRole(id=%q) status = %d, want %d", tt.pathID, w.Code, tt.wantStatus)
			}
		})
	}
}

func TestSourceHandler_SetRole_RoleValidation(t *testing.T) {
	t.Parallel()

	validID := uuid.New().String()

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "malformed JSON",
			body:       `{bad}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid role value",
			body:       `{"role":"superadmin"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid role — SQL injection",
			body:       `{"role":"';DROP-TABLE-sources;--"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid role — XSS",
			body:       `{"role":"<script>alert(1)</script>"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "null role — clears assignment (valid, reaches store)",
			body: `{"role":null}`,
			// nil store will panic here — this path requires integration.
			// Documented: nil role clears assignment, reaches store.ClearSourceRole.
			// wantStatus intentionally omitted — skip this subtest with store=nil.
		},
	}

	for _, tt := range tests {
		if tt.wantStatus == 0 {
			continue // skip store-dependent paths
		}
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestSourceHandler(t)
			req := httptest.NewRequest(http.MethodPut, "/api/admin/notion-sources/"+validID+"/role", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", validID)
			w := httptest.NewRecorder()

			h.SetRole(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("SetRole(body=%q) status = %d, want %d (response: %s)", tt.name, w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

// ============================================================================
// SourceHandler.Create — JSON body validation
// ============================================================================

func TestSourceHandler_Create_ValidationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantMsg    string
	}{
		{
			name:       "malformed JSON",
			body:       `{not valid`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing database_id and name",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "database_id and name are required",
		},
		{
			name:       "missing name",
			body:       `{"database_id":"abc-db-id"}`,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "database_id and name are required",
		},
		{
			name:       "missing database_id",
			body:       `{"name":"My DB"}`,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "database_id and name are required",
		},
		{
			name:       "invalid role in body",
			body:       `{"database_id":"db-1","name":"Test","role":"overlord"}`,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "invalid role",
		},
		{
			name:       "invalid sync_mode",
			body:       `{"database_id":"db-1","name":"Test","sync_mode":"push"}`,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "invalid sync_mode",
		},
		{
			name:       "invalid poll_interval",
			body:       `{"database_id":"db-1","name":"Test","poll_interval":"3 seconds"}`,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "invalid poll_interval",
		},
		// "notjson" is valid JSON (a string). Use truly broken JSON:
		// We can't embed broken JSON inside valid JSON — the outer json.Decode fails first.
		// property_map validation is tested directly in TestValidateCreateSourceParams.
		{
			name:       "name too long",
			body:       fmt.Sprintf(`{"database_id":"db-1","name":%q}`, strings.Repeat("n", 256)),
			wantStatus: http.StatusBadRequest,
			wantMsg:    "name exceeds 255 characters",
		},
		{
			name:       "database_id too long",
			body:       fmt.Sprintf(`{"database_id":%q,"name":"OK"}`, strings.Repeat("d", 256)),
			wantStatus: http.StatusBadRequest,
			wantMsg:    "database_id exceeds 255 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestSourceHandler(t)
			req := httptest.NewRequest(http.MethodPost, "/api/admin/notion-sources", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			h.Create(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Create(%q) status = %d, want %d (response: %s)", tt.name, w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantMsg != "" && !strings.Contains(w.Body.String(), tt.wantMsg) {
				t.Errorf("Create(%q) response body = %s, want to contain %q", tt.name, w.Body.String(), tt.wantMsg)
			}
		})
	}
}

// TestSourceHandler_Create_OversizedBody verifies that the 1 MB body limit
// on api.Decode triggers a 400 before validation.
func TestSourceHandler_Create_OversizedBody(t *testing.T) {
	t.Parallel()

	// Body exceeds 1 MB — api.Decode uses MaxBytesReader internally.
	oversized := strings.Repeat("x", (1<<20)+1)
	body := fmt.Sprintf(`{"database_id":"db","name":%q}`, oversized)

	h := newTestSourceHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/notion-sources", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Create(oversized) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ============================================================================
// SourceHandler.Discover — nil client guard
// ============================================================================

func TestSourceHandler_Discover_NilClient(t *testing.T) {
	t.Parallel()

	// NewSourceHandler with nil client triggers the "not implemented" guard.
	h := newTestSourceHandler(t) // client is nil
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()

	h.Discover(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("Discover(nil client) status = %d, want %d", w.Code, http.StatusNotImplemented)
	}

	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Discover(nil client) decoding response: %v", err)
	}
	if diff := cmp.Diff("NOT_IMPLEMENTED", resp.Error.Code); diff != "" {
		t.Errorf("Discover(nil client) error code mismatch (-want +got):\n%s", diff)
	}
}

// ============================================================================
// SourceHandler.List — nil store boundary documentation
// ============================================================================

// TestSourceHandler_List_NilStore_IntegrationOnly documents that List calls
// h.store.Sources unconditionally. With a nil store it will panic. This test
// verifies that the handler has no pre-store validation to test at the unit
// level — all List testing requires integration tests with a real store.
//
// This test exists to record the boundary explicitly, not to run production code.
func TestSourceHandler_List_NilStore_IntegrationOnly(t *testing.T) {
	// This is intentionally NOT parallel — it documents a design constraint.
	// not parallel: documents nil-store panic boundary
	t.Log("SourceHandler.List calls store.Sources immediately with no prior validation.")
	t.Log("There is no pre-store code path to test at the handler unit level.")
	t.Log("All List testing belongs in store_integration_test.go.")
}
