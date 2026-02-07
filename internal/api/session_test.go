package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestSessionManager() *sessionManager {
	return &sessionManager{
		hmacSecret: []byte("test-secret-at-least-32-characters!!"),
		isDev:      true,
		logger:     slog.New(slog.DiscardHandler),
	}
}

// csrfTokenWithTimestamp creates a CSRF token with a specific timestamp for testing expiration.
func csrfTokenWithTimestamp(secret []byte, sessionID uuid.UUID, ts int64) string {
	msg := fmt.Sprintf("%s:%d", sessionID.String(), ts)
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(msg))
	sig := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("%d:%s", ts, sig)
}

func TestNewCSRFToken_RoundTrip(t *testing.T) {
	sm := newTestSessionManager()
	sessionID := uuid.New()

	token := sm.NewCSRFToken(sessionID)
	if token == "" {
		t.Fatal("NewCSRFToken() returned empty token")
	}

	if err := sm.CheckCSRF(sessionID, token); err != nil {
		t.Fatalf("CheckCSRF(valid token) error: %v", err)
	}
}

func TestCSRFToken_WrongSession(t *testing.T) {
	sm := newTestSessionManager()
	sessionID := uuid.New()
	otherID := uuid.New()

	token := sm.NewCSRFToken(sessionID)

	if err := sm.CheckCSRF(otherID, token); err == nil {
		t.Error("CheckCSRF(wrong session) expected error, got nil")
	}
}

func TestCSRFToken_WrongSecret(t *testing.T) {
	sm1 := newTestSessionManager()
	sm2 := &sessionManager{
		hmacSecret: []byte("different-secret-at-least-32-chars!!"),
		logger:     slog.New(slog.DiscardHandler),
	}

	sessionID := uuid.New()
	token := sm1.NewCSRFToken(sessionID)

	if err := sm2.CheckCSRF(sessionID, token); err == nil {
		t.Error("CheckCSRF(wrong secret) expected error, got nil")
	}
}

func TestCSRFToken_Malformed(t *testing.T) {
	sm := newTestSessionManager()
	sessionID := uuid.New()

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no_colon", "justtext"},
		{"bad_timestamp", "notanumber:signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sm.CheckCSRF(sessionID, tt.token)
			if err == nil {
				t.Errorf("CheckCSRF(%q) expected error, got nil", tt.token)
			}
		})
	}
}

func TestCSRFToken_Expired(t *testing.T) {
	sm := newTestSessionManager()
	sessionID := uuid.New()

	// Construct a token with a timestamp 25 hours ago (exceeds 24h TTL)
	oldTimestamp := time.Now().Add(-25 * time.Hour).Unix()
	token := csrfTokenWithTimestamp(sm.hmacSecret, sessionID, oldTimestamp)

	err := sm.CheckCSRF(sessionID, token)
	if err == nil {
		t.Error("CheckCSRF(expired token) expected error, got nil")
	}
}

func TestNewPreSessionCSRFToken_RoundTrip(t *testing.T) {
	sm := newTestSessionManager()

	token := sm.NewPreSessionCSRFToken()
	if token == "" {
		t.Fatal("NewPreSessionCSRFToken() returned empty token")
	}

	if !isPreSessionToken(token) {
		t.Error("NewPreSessionCSRFToken() token should have pre: prefix")
	}

	if err := sm.CheckPreSessionCSRF(token); err != nil {
		t.Fatalf("CheckPreSessionCSRF(valid token) error: %v", err)
	}
}

func TestPreSessionCSRFToken_WrongSecret(t *testing.T) {
	sm1 := newTestSessionManager()
	sm2 := &sessionManager{
		hmacSecret: []byte("different-secret-at-least-32-chars!!"),
		logger:     slog.New(slog.DiscardHandler),
	}

	token := sm1.NewPreSessionCSRFToken()

	if err := sm2.CheckPreSessionCSRF(token); err == nil {
		t.Error("CheckPreSessionCSRF(wrong secret) expected error, got nil")
	}
}

func TestCSRFTokenEndpoint_PreSession(t *testing.T) {
	sm := newTestSessionManager()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)
	// No session cookie — should get pre-session token

	sm.csrfToken(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("csrfToken() status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	decodeData(t, w, &body)

	token := body["csrfToken"]
	if token == "" {
		t.Fatal("csrfToken() expected csrfToken in response")
	}

	if !isPreSessionToken(token) {
		t.Error("csrfToken(no cookie) token should be pre-session")
	}

	if err := sm.CheckPreSessionCSRF(token); err != nil {
		t.Fatalf("csrfToken() returned invalid pre-session token: %v", err)
	}
}

func TestDeleteSession_InvalidUUID(t *testing.T) {
	sm := newTestSessionManager()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/not-a-uuid", nil)
	r.SetPathValue("id", "not-a-uuid")

	sm.deleteSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("deleteSession(bad uuid) status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	body := decodeErrorEnvelope(t, w)

	if body.Code != "invalid_id" {
		t.Errorf("deleteSession(bad uuid) code = %q, want %q", body.Code, "invalid_id")
	}
}

func TestDeleteSession_MissingID(t *testing.T) {
	sm := newTestSessionManager()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/", nil)

	sm.deleteSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("deleteSession(missing id) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestGetSession_InvalidUUID(t *testing.T) {
	sm := newTestSessionManager()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/not-a-uuid", nil)
	r.SetPathValue("id", "not-a-uuid")

	sm.getSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("getSession(bad uuid) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestGetSession_MissingID(t *testing.T) {
	sm := newTestSessionManager()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/", nil)

	sm.getSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("getSession(missing id) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestGetSessionMessages_InvalidUUID(t *testing.T) {
	sm := newTestSessionManager()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/not-a-uuid/messages", nil)
	r.SetPathValue("id", "not-a-uuid")

	sm.getSessionMessages(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("getSessionMessages(bad uuid) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ============================================================================
// Session Ownership Tests
// ============================================================================

func TestRequireOwnership_NoSession(t *testing.T) {
	sm := newTestSessionManager()
	targetID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+targetID.String(), nil)
	r.SetPathValue("id", targetID.String())
	// No session in context — should return 403

	sm.getSession(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("getSession(no session cookie) status = %d, want %d", w.Code, http.StatusForbidden)
	}

	body := decodeErrorEnvelope(t, w)
	if body.Code != "forbidden" {
		t.Errorf("getSession(no session cookie) code = %q, want %q", body.Code, "forbidden")
	}
}

func TestRequireOwnership_Mismatch(t *testing.T) {
	sm := newTestSessionManager()
	ownerID := uuid.New()
	targetID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+targetID.String(), nil)
	r.SetPathValue("id", targetID.String())
	// Set a different session ID in context (simulates different cookie)
	ctx := context.WithValue(r.Context(), ctxKeySessionID, ownerID)
	r = r.WithContext(ctx)

	sm.getSession(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("getSession(mismatched session) status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestDeleteSession_OwnershipDenied(t *testing.T) {
	sm := newTestSessionManager()
	ownerID := uuid.New()
	targetID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+targetID.String(), nil)
	r.SetPathValue("id", targetID.String())
	ctx := context.WithValue(r.Context(), ctxKeySessionID, ownerID)
	r = r.WithContext(ctx)

	sm.deleteSession(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("deleteSession(not owner) status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestGetSessionMessages_OwnershipDenied(t *testing.T) {
	sm := newTestSessionManager()
	ownerID := uuid.New()
	targetID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+targetID.String()+"/messages", nil)
	r.SetPathValue("id", targetID.String())
	ctx := context.WithValue(r.Context(), ctxKeySessionID, ownerID)
	r = r.WithContext(ctx)

	sm.getSessionMessages(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("getSessionMessages(not owner) status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestListSessions_NoSession(t *testing.T) {
	sm := newTestSessionManager()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	// No session in context

	sm.listSessions(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("listSessions(no session) status = %d, want %d", w.Code, http.StatusOK)
	}

	// Should return empty list, not an error
	type sessionItem struct {
		ID string `json:"id"`
	}
	var items []sessionItem
	decodeData(t, w, &items)
	if len(items) != 0 {
		t.Errorf("listSessions(no session) returned %d items, want 0", len(items))
	}
}
