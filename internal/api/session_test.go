package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
	"github.com/koopa0/koopa/internal/session"
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

	// Construct a token with a timestamp 2 hours ago (exceeds 1h TTL)
	oldTimestamp := time.Now().Add(-2 * time.Hour).Unix()
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

	// Should return empty list with total=0, not an error.
	var body struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		Total int `json:"total"`
	}
	decodeData(t, w, &body)
	if len(body.Items) != 0 {
		t.Errorf("listSessions(no user) returned %d items, want 0", len(body.Items))
	}
	if body.Total != 0 {
		t.Errorf("listSessions(no user) total = %d, want 0", body.Total)
	}
}

// TestSignUID_RoundTrip verifies that signUID + verifySignedUID is a valid round-trip.
func TestSignUID_RoundTrip(t *testing.T) {
	t.Parallel()

	secret := []byte("test-secret-at-least-32-characters!!")
	uid := uuid.New().String()

	signed := signUID(uid, secret)
	got, ok := verifySignedUID(signed, secret)
	if !ok {
		t.Fatalf("verifySignedUID(%q) returned false, want true", signed)
	}
	if got != uid {
		t.Errorf("verifySignedUID(%q) = %q, want %q", signed, got, uid)
	}
}

// TestSignUID_TamperedSignature verifies that modifying the signature is detected.
func TestSignUID_TamperedSignature(t *testing.T) {
	t.Parallel()

	secret := []byte("test-secret-at-least-32-characters!!")
	uid := uuid.New().String()

	signed := signUID(uid, secret)
	// Tamper: change last character of signature
	tampered := signed[:len(signed)-1] + "X"

	if _, ok := verifySignedUID(tampered, secret); ok {
		t.Error("verifySignedUID(tampered) returned true, want false")
	}
}

// TestSignUID_TamperedUID verifies that modifying the UID is detected.
func TestSignUID_TamperedUID(t *testing.T) {
	t.Parallel()

	secret := []byte("test-secret-at-least-32-characters!!")
	uid := uuid.New().String()

	signed := signUID(uid, secret)
	// Replace UID portion with a different UUID
	otherUID := uuid.New().String()
	idx := len(uid)
	tampered := otherUID + signed[idx:]

	if _, ok := verifySignedUID(tampered, secret); ok {
		t.Error("verifySignedUID(tampered uid) returned true, want false")
	}
}

// TestSignUID_WrongSecret verifies that a different secret rejects the cookie.
func TestSignUID_WrongSecret(t *testing.T) {
	t.Parallel()

	secret1 := []byte("test-secret-at-least-32-characters!!")
	secret2 := []byte("different-secret-at-least-32-chars!!")
	uid := uuid.New().String()

	signed := signUID(uid, secret1)

	if _, ok := verifySignedUID(signed, secret2); ok {
		t.Error("verifySignedUID(wrong secret) returned true, want false")
	}
}

// TestSignUID_UnsignedCookie verifies that old unsigned cookies are rejected (graceful migration).
func TestSignUID_UnsignedCookie(t *testing.T) {
	t.Parallel()

	secret := []byte("test-secret-at-least-32-characters!!")
	// Plain UUID without signature — old format
	plainUID := uuid.New().String()

	if _, ok := verifySignedUID(plainUID, secret); ok {
		t.Error("verifySignedUID(unsigned cookie) returned true, want false")
	}
}

// TestSignUID_EmptyValue verifies that empty strings are rejected.
func TestSignUID_EmptyValue(t *testing.T) {
	t.Parallel()

	secret := []byte("test-secret-at-least-32-characters!!")

	if _, ok := verifySignedUID("", secret); ok {
		t.Error("verifySignedUID(\"\") returned true, want false")
	}
}

// TestUserID_SignedCookie verifies the full flow through UserID with a signed cookie.
func TestUserID_SignedCookie(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager()
	uid := uuid.New().String()

	signed := signUID(uid, sm.hmacSecret)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: userCookieName, Value: signed})

	got := sm.UserID(r)
	if got != uid {
		t.Errorf("UserID(signed cookie) = %q, want %q", got, uid)
	}
}

// TestUserID_UnsignedCookie verifies that old unsigned cookies are rejected.
func TestUserID_UnsignedCookie(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager()
	uid := uuid.New().String()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: userCookieName, Value: uid})

	got := sm.UserID(r)
	if got != "" {
		t.Errorf("UserID(unsigned cookie) = %q, want empty string", got)
	}
}

// TestUserID_NoCookie verifies that missing cookie returns empty string.
func TestUserID_NoCookie(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	got := sm.UserID(r)
	if got != "" {
		t.Errorf("UserID(no cookie) = %q, want empty string", got)
	}
}

// TestSetUserCookie_Signed verifies that setUserCookie writes a signed value.
func TestSetUserCookie_Signed(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager()
	uid := uuid.New().String()

	w := httptest.NewRecorder()
	sm.setUserCookie(w, uid)

	cookies := w.Result().Cookies()
	var uidCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == userCookieName {
			uidCookie = c
		}
	}
	if uidCookie == nil {
		t.Fatal("setUserCookie() did not set uid cookie")
	}

	// Cookie value should be signed (contains ".")
	if !strings.Contains(uidCookie.Value, ".") {
		t.Errorf("setUserCookie() value = %q, want signed format (uid.signature)", uidCookie.Value)
	}

	// Round-trip: verify the signed value
	got, ok := verifySignedUID(uidCookie.Value, sm.hmacSecret)
	if !ok {
		t.Fatalf("verifySignedUID(cookie value) returned false")
	}
	if got != uid {
		t.Errorf("verifySignedUID(cookie value) = %q, want %q", got, uid)
	}
}

// TestUserID_SignedNonUUID verifies that a validly signed cookie
// containing a non-UUID value is rejected by the UUID validation in UserID.
// SECURITY: prevents crafted ownerIDs from reaching SQL queries and advisory locks (CWE-20).
func TestUserID_SignedNonUUID(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager()
	// Sign a non-UUID value — HMAC is valid, but UUID parse fails.
	nonUUID := "not-a-uuid-at-all"
	signed := signUID(nonUUID, sm.hmacSecret)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: userCookieName, Value: signed})

	got := sm.UserID(r)
	if got != "" {
		t.Errorf("UserID(signed non-UUID) = %q, want empty string", got)
	}
}

func TestExportSession_MissingID(t *testing.T) {
	sm := newTestSessionManager()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions//export", nil)

	sm.exportSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("exportSession(missing id) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestExportSession_InvalidUUID(t *testing.T) {
	sm := newTestSessionManager()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/not-a-uuid/export", nil)
	r.SetPathValue("id", "not-a-uuid")

	sm.exportSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("exportSession(bad uuid) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestExportSession_NoUser(t *testing.T) {
	sm := newTestSessionManager()
	targetID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+targetID.String()+"/export", nil)
	r.SetPathValue("id", targetID.String())
	// No user in context — should return 403

	sm.exportSession(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("exportSession(no user) status = %d, want %d", w.Code, http.StatusForbidden)
	}

	body := decodeErrorEnvelope(t, w)
	if body.Code != "forbidden" {
		t.Errorf("exportSession(no user) code = %q, want %q", body.Code, "forbidden")
	}
}

func TestExportMarkdown(t *testing.T) {
	sm := newTestSessionManager()

	data := &session.ExportData{
		Session: &session.Session{
			ID:    uuid.New(),
			Title: "Test Chat",
		},
		Messages: []*session.Message{
			{Role: "user", Content: []*ai.Part{ai.NewTextPart("Hello")}},
			{Role: "assistant", Content: []*ai.Part{ai.NewTextPart("Hi there!")}},
		},
	}

	w := httptest.NewRecorder()
	sm.exportMarkdown(w, data)

	if w.Code != http.StatusOK {
		t.Fatalf("exportMarkdown() status = %d, want %d", w.Code, http.StatusOK)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "text/markdown; charset=utf-8" {
		t.Errorf("exportMarkdown() Content-Type = %q, want %q", ct, "text/markdown; charset=utf-8")
	}

	wantCD := mime.FormatMediaType("attachment", map[string]string{
		"filename": fmt.Sprintf("session-%s.md", data.Session.ID),
	})
	cd := w.Header().Get("Content-Disposition")
	if cd != wantCD {
		t.Errorf("exportMarkdown() Content-Disposition = %q, want %q", cd, wantCD)
	}

	body := w.Body.String()
	if !strings.Contains(body, "# Test Chat") {
		t.Errorf("exportMarkdown() body missing title, got: %s", body)
	}
	if !strings.Contains(body, "**User**: Hello") {
		t.Errorf("exportMarkdown() body missing user message, got: %s", body)
	}
	if !strings.Contains(body, "**Assistant**: Hi there!") {
		t.Errorf("exportMarkdown() body missing assistant message, got: %s", body)
	}
}

func TestExportMarkdown_UntitledSession(t *testing.T) {
	sm := newTestSessionManager()

	data := &session.ExportData{
		Session:  &session.Session{ID: uuid.New()},
		Messages: []*session.Message{},
	}

	w := httptest.NewRecorder()
	sm.exportMarkdown(w, data)

	body := w.Body.String()
	if !strings.Contains(body, "# Untitled Session") {
		t.Errorf("exportMarkdown(no title) body = %q, want '# Untitled Session'", body)
	}
}

func TestExportMarkdown_TitleWithNewlines(t *testing.T) {
	sm := newTestSessionManager()

	data := &session.ExportData{
		Session: &session.Session{
			ID:    uuid.New(),
			Title: "Line1\nLine2\rLine3",
		},
		Messages: []*session.Message{},
	}

	w := httptest.NewRecorder()
	sm.exportMarkdown(w, data)

	body := w.Body.String()
	wantHeading := "# Line1 Line2 Line3"
	firstLine := strings.SplitN(body, "\n", 2)[0]
	if firstLine != wantHeading {
		t.Errorf("exportMarkdown(title with newlines) first line = %q, want %q", firstLine, wantHeading)
	}
}

func TestExportMarkdown_ContentInjection(t *testing.T) {
	sm := newTestSessionManager()

	data := &session.ExportData{
		Session: &session.Session{
			ID:    uuid.New(),
			Title: "Test Chat",
		},
		Messages: []*session.Message{
			{Role: "user", Content: []*ai.Part{ai.NewTextPart("# Injected Heading\n## Sub-heading")}},
			{Role: "assistant", Content: []*ai.Part{ai.NewTextPart("Normal reply")}},
			{Role: "user", Content: []*ai.Part{ai.NewTextPart("Setext attack\n===")}},
		},
	}

	w := httptest.NewRecorder()
	sm.exportMarkdown(w, data)

	body := w.Body.String()

	// Leading # in message content should be escaped with backslash
	if strings.Contains(body, "**User**: # Injected") {
		t.Errorf("exportMarkdown() content heading not escaped, body contains unescaped '# Injected':\n%s", body)
	}
	if !strings.Contains(body, "**User**: \\# Injected Heading") {
		t.Errorf("exportMarkdown() expected escaped heading '\\# Injected Heading' in body:\n%s", body)
	}
	if !strings.Contains(body, "\\## Sub-heading") {
		t.Errorf("exportMarkdown() expected escaped sub-heading '\\## Sub-heading' in body:\n%s", body)
	}
	// Setext underline should be escaped
	if !strings.Contains(body, "\\===") {
		t.Errorf("exportMarkdown() setext underline not escaped, body:\n%s", body)
	}
	// Normal content should be unaffected
	if !strings.Contains(body, "**Assistant**: Normal reply") {
		t.Errorf("exportMarkdown() normal content should be unchanged, body:\n%s", body)
	}
}

func TestSanitizeMarkdownContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "no headings", input: "normal text", want: "normal text"},
		{name: "heading escaped", input: "# Heading", want: "\\# Heading"},
		{name: "sub heading", input: "## Sub", want: "\\## Sub"},
		{name: "indented heading", input: "  # Indented", want: "  \\# Indented"},
		{name: "not at start", input: "text # not heading", want: "text # not heading"},
		{name: "multiline", input: "line1\n# heading\nline3", want: "line1\n\\# heading\nline3"},
		{name: "setext h1", input: "title\n===", want: "title\n\\==="},
		{name: "setext h2", input: "title\n---", want: "title\n\\---"},
		{name: "setext long", input: "title\n=======", want: "title\n\\======="},
		{name: "setext indented", input: "title\n  ---", want: "title\n  \\---"},
		{name: "not setext mixed", input: "=-=", want: "=-="},
		{name: "empty string", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeMarkdownContent(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeMarkdownContent(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
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

func FuzzVerifySignedUID(f *testing.F) {
	secret := []byte("test-secret-at-least-32-characters!!")
	uid := uuid.New().String()
	validSigned := signUID(uid, secret)

	f.Add(validSigned)
	f.Add(uid) // unsigned
	f.Add("")
	f.Add(".")
	f.Add("uid.badsig")
	f.Add("uid.badsig.extra")
	f.Add(uid + ".AAAA")

	f.Fuzz(func(t *testing.T, value string) {
		_, _ = verifySignedUID(value, secret) // must not panic
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
