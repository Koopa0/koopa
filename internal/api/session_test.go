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
func csrfTokenWithTimestamp(secret []byte, userID string, ts int64) string {
	msg := fmt.Sprintf("%s:%d", userID, ts)
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(msg))
	sig := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("%d:%s", ts, sig)
}

func TestNewCSRFToken_RoundTrip(t *testing.T) {
	sm := newTestSessionManager()
	userID := uuid.New().String()

	token := sm.NewCSRFToken(userID)
	if token == "" {
		t.Fatal("NewCSRFToken() returned empty token")
	}

	if err := sm.CheckCSRF(userID, token); err != nil {
		t.Fatalf("CheckCSRF(valid token) error: %v", err)
	}
}

func TestCSRFToken_WrongUser(t *testing.T) {
	sm := newTestSessionManager()
	userID := uuid.New().String()
	otherID := uuid.New().String()

	token := sm.NewCSRFToken(userID)

	if err := sm.CheckCSRF(otherID, token); err == nil {
		t.Error("CheckCSRF(wrong user) expected error, got nil")
	}
}

func TestCSRFToken_WrongSecret(t *testing.T) {
	sm1 := newTestSessionManager()
	sm2 := &sessionManager{
		hmacSecret: []byte("different-secret-at-least-32-chars!!"),
		logger:     slog.New(slog.DiscardHandler),
	}

	userID := uuid.New().String()
	token := sm1.NewCSRFToken(userID)

	if err := sm2.CheckCSRF(userID, token); err == nil {
		t.Error("CheckCSRF(wrong secret) expected error, got nil")
	}
}

func TestCSRFToken_Malformed(t *testing.T) {
	sm := newTestSessionManager()
	userID := uuid.New().String()

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "no_colon", token: "justtext"},
		{name: "bad_timestamp", token: "notanumber:signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sm.CheckCSRF(userID, tt.token)
			if err == nil {
				t.Errorf("CheckCSRF(%q) expected error, got nil", tt.token)
			}
		})
	}
}

func TestCSRFToken_Expired(t *testing.T) {
	sm := newTestSessionManager()
	userID := uuid.New().String()

	// Construct a token with a timestamp 25 hours ago (exceeds 24h TTL)
	oldTimestamp := time.Now().Add(-25 * time.Hour).Unix()
	token := csrfTokenWithTimestamp(sm.hmacSecret, userID, oldTimestamp)

	err := sm.CheckCSRF(userID, token)
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
	// No uid cookie — should get pre-session token

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
		t.Error("csrfToken(no uid) token should be pre-session")
	}

	if err := sm.CheckPreSessionCSRF(token); err != nil {
		t.Fatalf("csrfToken() returned invalid pre-session token: %v", err)
	}
}

func TestCSRFTokenEndpoint_WithUser(t *testing.T) {
	sm := newTestSessionManager()
	userID := uuid.New().String()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)
	ctx := context.WithValue(r.Context(), ctxKeyUserID, userID)
	r = r.WithContext(ctx)

	sm.csrfToken(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("csrfToken() status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	decodeData(t, w, &body)

	token := body["csrfToken"]
	if isPreSessionToken(token) {
		t.Error("csrfToken(with uid) should not be pre-session")
	}

	if err := sm.CheckCSRF(userID, token); err != nil {
		t.Fatalf("csrfToken() returned invalid user-bound token: %v", err)
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

func TestRequireOwnership_NoUser(t *testing.T) {
	sm := newTestSessionManager()
	targetID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+targetID.String(), nil)
	r.SetPathValue("id", targetID.String())
	// No user in context — should return 403

	sm.getSession(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("getSession(no user) status = %d, want %d", w.Code, http.StatusForbidden)
	}

	body := decodeErrorEnvelope(t, w)
	if body.Code != "forbidden" {
		t.Errorf("getSession(no user) code = %q, want %q", body.Code, "forbidden")
	}
}

func TestDeleteSession_NoUser(t *testing.T) {
	sm := newTestSessionManager()
	targetID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+targetID.String(), nil)
	r.SetPathValue("id", targetID.String())
	// No user in context

	sm.deleteSession(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("deleteSession(no user) status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestGetSessionMessages_NoUser(t *testing.T) {
	sm := newTestSessionManager()
	targetID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+targetID.String()+"/messages", nil)
	r.SetPathValue("id", targetID.String())
	// No user in context

	sm.getSessionMessages(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("getSessionMessages(no user) status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestListSessions_NoUser(t *testing.T) {
	sm := newTestSessionManager()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	// No user in context

	sm.listSessions(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("listSessions(no user) status = %d, want %d", w.Code, http.StatusOK)
	}

	// Should return empty list, not an error
	type sessionItem struct {
		ID string `json:"id"`
	}
	var items []sessionItem
	decodeData(t, w, &items)
	if len(items) != 0 {
		t.Errorf("listSessions(no user) returned %d items, want 0", len(items))
	}
}

func FuzzCheckCSRF(f *testing.F) {
	sm := newTestSessionManager()
	userID := uuid.New().String()
	validToken := sm.NewCSRFToken(userID)

	f.Add(userID, validToken)
	f.Add(userID, "")
	f.Add(userID, "notanumber:signature")
	f.Add(userID, "12345:badsig")
	f.Add(uuid.New().String(), validToken)
	f.Add("", "")
	f.Add("not-a-uuid", "1234:sig")

	f.Fuzz(func(t *testing.T, uid, token string) {
		_ = sm.CheckCSRF(uid, token) // must not panic
	})
}

func FuzzCheckPreSessionCSRF(f *testing.F) {
	sm := newTestSessionManager()
	validToken := sm.NewPreSessionCSRFToken()

	f.Add(validToken)
	f.Add("")
	f.Add("pre:")
	f.Add("pre:nonce:notanumber:sig")
	f.Add("pre:abc:12345:sig")
	f.Add("notpre:abc:123:sig")
	f.Add("pre:abc:12345:sig:extra")

	f.Fuzz(func(t *testing.T, token string) {
		_ = sm.CheckPreSessionCSRF(token) // must not panic
	})
}

func BenchmarkNewCSRFToken(b *testing.B) {
	sm := newTestSessionManager()
	userID := uuid.New().String()
	for b.Loop() {
		sm.NewCSRFToken(userID)
	}
}

func BenchmarkCheckCSRF(b *testing.B) {
	sm := newTestSessionManager()
	userID := uuid.New().String()
	token := sm.NewCSRFToken(userID)
	for b.Loop() {
		_ = sm.CheckCSRF(userID, token)
	}
}
