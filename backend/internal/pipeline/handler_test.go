package pipeline

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/koopa0/blog-backend/internal/webhook"
)

const testSecret = "test-webhook-secret-32chars-long!" //nolint:gosec // test credential

// signPayload computes the HMAC-SHA256 signature for a webhook body.
func signPayload(t *testing.T, body []byte, secret string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// newTestRouter returns a WebhookRouter with minimal dependencies for HTTP tests.
func newTestRouter(t *testing.T) *WebhookRouter {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	return NewWebhookRouter(testSecret, "owner/obsidian-vault", "bot-user", nil, logger)
}

// syncBG runs background functions synchronously for testing.
func syncBG(_ string, fn func()) {
	fn()
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

func TestWebhookHandle_SignatureVerification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		signature  string
		wantStatus int
	}{
		{
			name:       "missing signature",
			signature:  "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong prefix",
			signature:  "md5=abc123",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid hex",
			signature:  "sha256=not-valid-hex!!!",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong secret",
			signature:  "placeholder", // will be overridden per-test
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			wr := newTestRouter(t)

			body := []byte(`{"ref":"refs/heads/main"}`)
			sig := tt.signature
			// for "wrong secret" case, sign with a different key
			if tt.name == "wrong secret" {
				sig = signPayload(t, body, "completely-wrong-secret-key-here!")
			}

			req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
			req.Header.Set("X-Hub-Signature-256", sig)
			req.Header.Set("X-GitHub-Event", "push")
			w := httptest.NewRecorder()

			wr.Handle(w, req, syncBG)

			if w.Code != tt.wantStatus {
				t.Errorf("Handle() status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}

	t.Run("valid signature accepted", func(t *testing.T) {
		t.Parallel()
		wr := newTestRouter(t)

		body := []byte(`{"ref":"refs/heads/other","repository":{"full_name":"other/repo"},"sender":{"login":"user"},"commits":[]}`)
		sig := signPayload(t, body, testSecret)

		req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
		req.Header.Set("X-Hub-Signature-256", sig)
		req.Header.Set("X-GitHub-Event", "push")
		w := httptest.NewRecorder()

		wr.Handle(w, req, syncBG)

		// non-main branch push returns 200 OK (accepted but no-op)
		if w.Code != http.StatusOK {
			t.Errorf("Handle() status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

// ---------------------------------------------------------------------------
// HMAC forgery: modified body with original signature
// ---------------------------------------------------------------------------

func TestWebhookHandle_HMACForgery(t *testing.T) {
	t.Parallel()
	wr := newTestRouter(t)

	original := []byte(`{"ref":"refs/heads/main","commits":[]}`)
	sig := signPayload(t, original, testSecret)

	// attacker modifies the body but reuses the original signature
	tampered := []byte(`{"ref":"refs/heads/main","commits":[{"message":"pwned"}]}`)

	req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(tampered))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "push")
	w := httptest.NewRecorder()

	wr.Handle(w, req, syncBG)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Handle() with tampered body: status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// ---------------------------------------------------------------------------
// Deduplication: same delivery ID twice
// ---------------------------------------------------------------------------

func TestWebhookHandle_Deduplication(t *testing.T) {
	t.Parallel()
	wr := newTestRouter(t)
	dedup := webhook.NewDeduplicationCache(5 * time.Minute)
	t.Cleanup(dedup.Stop)
	wr.WithDedup(dedup)

	body := makePushBody(t, "refs/heads/other", "owner/other-repo", "user", nil)
	sig := signPayload(t, body, testSecret)

	// first delivery
	req1 := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
	req1.Header.Set("X-Hub-Signature-256", sig)
	req1.Header.Set("X-GitHub-Event", "push")
	req1.Header.Set("X-GitHub-Delivery", "delivery-123")
	w1 := httptest.NewRecorder()
	wr.Handle(w1, req1, syncBG)

	// second delivery with same ID
	req2 := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
	req2.Header.Set("X-Hub-Signature-256", sig)
	req2.Header.Set("X-GitHub-Event", "push")
	req2.Header.Set("X-GitHub-Delivery", "delivery-123")
	w2 := httptest.NewRecorder()
	wr.Handle(w2, req2, syncBG)

	if w2.Code != http.StatusOK {
		t.Errorf("second delivery: status = %d, want %d (deduplicated)", w2.Code, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// Bot self-loop protection
// ---------------------------------------------------------------------------

func TestWebhookHandle_BotSelfLoop(t *testing.T) {
	t.Parallel()
	wr := newTestRouter(t)

	body := makePushBody(t, "refs/heads/main", "owner/obsidian-vault", "bot-user", nil)
	sig := signPayload(t, body, testSecret)

	req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "push")
	w := httptest.NewRecorder()

	wr.Handle(w, req, syncBG)

	if w.Code != http.StatusOK {
		t.Errorf("bot self-loop: status = %d, want %d", w.Code, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// Body size limit (1 MB)
// ---------------------------------------------------------------------------

func TestWebhookHandle_OversizedBody(t *testing.T) {
	t.Parallel()
	wr := newTestRouter(t)

	// create a body slightly over 1MB
	oversized := make([]byte, 1<<20+1)
	for i := range oversized {
		oversized[i] = 'x'
	}

	sig := signPayload(t, oversized, testSecret)
	req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(oversized))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "push")
	w := httptest.NewRecorder()

	wr.Handle(w, req, syncBG)

	if w.Code != http.StatusBadRequest {
		t.Errorf("oversized body: status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// Event routing
// ---------------------------------------------------------------------------

func TestWebhookHandle_EventRouting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		eventType  string
		wantStatus int
	}{
		{name: "unknown event type ignored", eventType: "issues", wantStatus: http.StatusOK},
		{name: "empty event type ignored", eventType: "", wantStatus: http.StatusOK},
		{name: "ping event ignored", eventType: "ping", wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			wr := newTestRouter(t)

			body := []byte(`{}`)
			sig := signPayload(t, body, testSecret)

			req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
			req.Header.Set("X-Hub-Signature-256", sig)
			req.Header.Set("X-GitHub-Event", tt.eventType)
			w := httptest.NewRecorder()

			wr.Handle(w, req, syncBG)

			if w.Code != tt.wantStatus {
				t.Errorf("Handle(%q event) status = %d, want %d", tt.eventType, w.Code, tt.wantStatus)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Push: non-main branch ignored
// ---------------------------------------------------------------------------

func TestWebhookHandle_NonMainBranch(t *testing.T) {
	t.Parallel()
	wr := newTestRouter(t)

	branches := []string{
		"refs/heads/feature/my-branch",
		"refs/heads/develop",
		"refs/tags/v1.0.0",
	}

	for _, ref := range branches {
		t.Run(ref, func(t *testing.T) {
			t.Parallel()
			body := makePushBody(t, ref, "owner/obsidian-vault", "user", nil)
			sig := signPayload(t, body, testSecret)

			req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
			req.Header.Set("X-Hub-Signature-256", sig)
			req.Header.Set("X-GitHub-Event", "push")
			w := httptest.NewRecorder()

			wr.Handle(w, req, syncBG)

			if w.Code != http.StatusOK {
				t.Errorf("Handle(%q) status = %d, want %d (ignored)", ref, w.Code, http.StatusOK)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Push: malformed JSON
// ---------------------------------------------------------------------------

func TestWebhookHandle_MalformedPushJSON(t *testing.T) {
	t.Parallel()
	wr := newTestRouter(t)

	body := []byte(`{not valid json`)
	sig := signPayload(t, body, testSecret)

	req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "push")
	w := httptest.NewRecorder()

	wr.Handle(w, req, syncBG)

	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON: status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// PR: only merged PRs are processed
// ---------------------------------------------------------------------------

func TestWebhookHandle_PRRouting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		action     string
		merged     bool
		wantStatus int
	}{
		{name: "opened PR ignored", action: "opened", merged: false, wantStatus: http.StatusOK},
		{name: "closed but not merged", action: "closed", merged: false, wantStatus: http.StatusOK},
		{name: "synchronize ignored", action: "synchronize", merged: false, wantStatus: http.StatusOK},
		// merged PR with no notionTasks configured returns 200
		{name: "merged PR no notion", action: "closed", merged: true, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			wr := newTestRouter(t)

			body := makePRBody(t, tt.action, tt.merged, "")
			sig := signPayload(t, body, testSecret)

			req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
			req.Header.Set("X-Hub-Signature-256", sig)
			req.Header.Set("X-GitHub-Event", "pull_request")
			w := httptest.NewRecorder()

			wr.Handle(w, req, syncBG)

			if w.Code != tt.wantStatus {
				t.Errorf("PR(%q, merged=%v) status = %d, want %d", tt.action, tt.merged, w.Code, tt.wantStatus)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// PR: malformed JSON
// ---------------------------------------------------------------------------

func TestWebhookHandle_MalformedPRJSON(t *testing.T) {
	t.Parallel()
	wr := newTestRouter(t)

	body := []byte(`{"action": "closed", "pull_request": INVALID}`)
	sig := signPayload(t, body, testSecret)

	req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "pull_request")
	w := httptest.NewRecorder()

	wr.Handle(w, req, syncBG)

	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed PR JSON: status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// Push: obsidian repo with no changed markdown returns 200
// ---------------------------------------------------------------------------

func TestWebhookHandle_NoMarkdownChanges(t *testing.T) {
	t.Parallel()
	wr := newTestRouter(t)

	commits := []PushCommit{
		{Added: []string{"image.png"}, Modified: []string{"config.yml"}},
	}
	body := makePushBody(t, "refs/heads/main", "owner/obsidian-vault", "user", commits)
	sig := signPayload(t, body, testSecret)

	req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "push")
	w := httptest.NewRecorder()

	wr.Handle(w, req, syncBG)

	if w.Code != http.StatusOK {
		t.Errorf("no markdown changes: status = %d, want %d", w.Code, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// Handler facade: backpressure (semaphore full)
// ---------------------------------------------------------------------------

func TestGoBackground_Backpressure(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	h := NewHandler(nil, nil, nil, logger)

	// fill all semaphore slots
	blocker := make(chan struct{})
	for range maxConcurrentOps {
		h.goBackground("blocker", func() {
			<-blocker
		})
	}

	// next operation should be dropped
	dropped := true
	h.goBackground("overflow", func() {
		dropped = false
	})

	// release blockers
	close(blocker)
	h.Wait()

	if !dropped {
		t.Error("goBackground did not drop operation when at capacity")
	}
}

// ---------------------------------------------------------------------------
// Adversarial: empty body
// ---------------------------------------------------------------------------

func TestWebhookHandle_EmptyBody(t *testing.T) {
	t.Parallel()
	wr := newTestRouter(t)

	body := []byte{}
	sig := signPayload(t, body, testSecret)

	req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "push")
	w := httptest.NewRecorder()

	wr.Handle(w, req, syncBG)

	// empty body fails JSON parse → 400
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty body: status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// Push: obsidian repo main with no changed files returns 200
// ---------------------------------------------------------------------------

func TestWebhookHandle_ObsidianMainNoChangedFiles(t *testing.T) {
	t.Parallel()
	wr := newTestRouter(t)

	body := makePushBody(t, "refs/heads/main", "owner/obsidian-vault", "user", nil)
	sig := signPayload(t, body, testSecret)

	req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "push")
	w := httptest.NewRecorder()

	wr.Handle(w, req, syncBG)

	// no public or knowledge files → 200 OK
	if w.Code != http.StatusOK {
		t.Errorf("obsidian main no files: status = %d, want %d", w.Code, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// Adversarial: null bytes in header
// ---------------------------------------------------------------------------

func TestWebhookHandle_NullBytesInHeader(t *testing.T) {
	t.Parallel()
	wr := newTestRouter(t)

	body := []byte(`{}`)
	sig := signPayload(t, body, testSecret)

	req := httptest.NewRequest("POST", "/api/webhook/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "push\x00injection")
	w := httptest.NewRecorder()

	wr.Handle(w, req, syncBG)

	// null byte event type doesn't match any known event → 200 (ignored)
	if w.Code != http.StatusOK {
		t.Errorf("null byte event: status = %d, want %d", w.Code, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func makePushBody(t *testing.T, ref, repo, sender string, commits []PushCommit) []byte {
	t.Helper()
	evt := PushEvent{
		Ref:        ref,
		Repository: PushRepository{FullName: repo},
		Sender:     PushSender{Login: sender},
		Commits:    commits,
	}
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshaling push event: %v", err)
	}
	return data
}

func makePRBody(t *testing.T, action string, merged bool, body string) []byte {
	t.Helper()
	evt := PullRequestEvent{
		Action: action,
		PullRequest: PullRequestData{
			Number: 42,
			Title:  "test PR",
			Body:   body,
			Merged: merged,
		},
		Repository: PushRepository{FullName: "owner/repo"},
		Sender:     PushSender{Login: "user"},
	}
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshaling PR event: %v", err)
	}
	return data
}
