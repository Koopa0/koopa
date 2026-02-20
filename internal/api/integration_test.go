//go:build integration

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"

	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/sqlc"
	"github.com/koopa0/koopa/internal/testutil"
)

const testOwnerID = "test-user"

// setupIntegrationSessionManager creates a sessionManager backed by the shared PostgreSQL database.
// Tables are truncated for isolation.
func setupIntegrationSessionManager(t *testing.T) *sessionManager {
	t.Helper()

	testutil.CleanTables(t, sharedDB.Pool)

	store := session.New(sqlc.New(sharedDB.Pool), sharedDB.Pool, slog.New(slog.DiscardHandler))

	return &sessionManager{
		store:      store,
		hmacSecret: []byte("test-secret-at-least-32-characters!!"),
		isDev:      true,
		logger:     slog.New(slog.DiscardHandler),
	}
}

func TestCreateSession_Success(t *testing.T) {
	sm := setupIntegrationSessionManager(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)

	// Inject user identity into context (normally done by userMiddleware)
	ctx := context.WithValue(r.Context(), ctxKeyUserID, testOwnerID)
	r = r.WithContext(ctx)

	sm.createSession(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("createSession() status = %d, want %d\nbody: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var resp map[string]string
	decodeData(t, w, &resp)

	// Should return a valid UUID
	if _, err := uuid.Parse(resp["id"]); err != nil {
		t.Errorf("createSession() id = %q, want valid UUID", resp["id"])
	}

	// Should return a CSRF token bound to the user
	if resp["csrfToken"] == "" {
		t.Error("createSession() expected csrfToken in response")
	}

	// Should set a session cookie
	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "sid" {
			found = true
			if c.Value != resp["id"] {
				t.Errorf("createSession() cookie sid = %q, want %q", c.Value, resp["id"])
			}
			if !c.HttpOnly {
				t.Error("createSession() cookie should be HttpOnly")
			}
		}
	}
	if !found {
		t.Error("createSession() expected sid cookie to be set")
	}
}

func TestGetSession_Success(t *testing.T) {
	sm := setupIntegrationSessionManager(t)
	ctx := context.Background()

	// Create a session first
	sess, err := sm.store.CreateSession(ctx, testOwnerID, "Test Session")
	if err != nil {
		t.Fatalf("setup: CreateSession() error: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sess.ID.String(), nil)
	r.SetPathValue("id", sess.ID.String())

	// Inject user identity for ownership check
	rctx := context.WithValue(r.Context(), ctxKeyUserID, testOwnerID)
	r = r.WithContext(rctx)

	sm.getSession(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("getSession(%s) status = %d, want %d\nbody: %s", sess.ID, w.Code, http.StatusOK, w.Body.String())
	}

	var resp struct {
		ID           string `json:"id"`
		Title        string `json:"title"`
		MessageCount int    `json:"messageCount"`
		CreatedAt    string `json:"createdAt"`
		UpdatedAt    string `json:"updatedAt"`
	}
	decodeData(t, w, &resp)

	if resp.ID != sess.ID.String() {
		t.Errorf("getSession() id = %q, want %q", resp.ID, sess.ID.String())
	}
	if resp.Title != "Test Session" {
		t.Errorf("getSession() title = %q, want %q", resp.Title, "Test Session")
	}
	if resp.CreatedAt == "" {
		t.Error("getSession() expected createdAt in response")
	}
	if resp.UpdatedAt == "" {
		t.Error("getSession() expected updatedAt in response")
	}
}

func TestGetSession_NotFound(t *testing.T) {
	sm := setupIntegrationSessionManager(t)

	missingID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+missingID.String(), nil)
	r.SetPathValue("id", missingID.String())

	// Set user identity (session doesn't exist, so ownership check returns 404)
	rctx := context.WithValue(r.Context(), ctxKeyUserID, testOwnerID)
	r = r.WithContext(rctx)

	sm.getSession(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("getSession(missing) status = %d, want %d", w.Code, http.StatusNotFound)
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "not_found" {
		t.Errorf("getSession(missing) code = %q, want %q", errResp.Code, "not_found")
	}
}

func TestListSessions_WithSession(t *testing.T) {
	sm := setupIntegrationSessionManager(t)
	ctx := context.Background()

	// Create a session
	sess, err := sm.store.CreateSession(ctx, testOwnerID, "My Chat")
	if err != nil {
		t.Fatalf("setup: CreateSession() error: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)

	// Inject user identity for listing
	rctx := context.WithValue(r.Context(), ctxKeyUserID, testOwnerID)
	r = r.WithContext(rctx)

	sm.listSessions(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("listSessions() status = %d, want %d\nbody: %s", w.Code, http.StatusOK, w.Body.String())
	}

	type sessionItem struct {
		ID           string `json:"id"`
		Title        string `json:"title"`
		MessageCount int    `json:"messageCount"`
		UpdatedAt    string `json:"updatedAt"`
	}
	var body struct {
		Items []sessionItem `json:"items"`
		Total int           `json:"total"`
	}
	decodeData(t, w, &body)

	if len(body.Items) != 1 {
		t.Fatalf("listSessions() returned %d items, want 1", len(body.Items))
	}
	if body.Items[0].ID != sess.ID.String() {
		t.Errorf("listSessions() items[0].id = %q, want %q", body.Items[0].ID, sess.ID.String())
	}
	if body.Items[0].Title != "My Chat" {
		t.Errorf("listSessions() items[0].title = %q, want %q", body.Items[0].Title, "My Chat")
	}
	if body.Items[0].UpdatedAt == "" {
		t.Error("listSessions() expected updatedAt in item")
	}
	if body.Total != 1 {
		t.Errorf("listSessions() total = %d, want 1", body.Total)
	}
}

func TestGetSessionMessages_Empty(t *testing.T) {
	sm := setupIntegrationSessionManager(t)
	ctx := context.Background()

	// Create a session with no messages
	sess, err := sm.store.CreateSession(ctx, testOwnerID, "")
	if err != nil {
		t.Fatalf("setup: CreateSession() error: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sess.ID.String()+"/messages", nil)
	r.SetPathValue("id", sess.ID.String())

	rctx := context.WithValue(r.Context(), ctxKeyUserID, testOwnerID)
	r = r.WithContext(rctx)

	sm.getSessionMessages(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("getSessionMessages(empty) status = %d, want %d\nbody: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var body struct {
		Items []json.RawMessage `json:"items"`
		Total int               `json:"total"`
	}
	decodeData(t, w, &body)

	if len(body.Items) != 0 {
		t.Errorf("getSessionMessages(empty) returned %d items, want 0", len(body.Items))
	}
	if body.Total != 0 {
		t.Errorf("getSessionMessages(empty) total = %d, want 0", body.Total)
	}
}

func TestDeleteSession_Success(t *testing.T) {
	sm := setupIntegrationSessionManager(t)
	ctx := context.Background()

	// Create a session
	sess, err := sm.store.CreateSession(ctx, testOwnerID, "To Delete")
	if err != nil {
		t.Fatalf("setup: CreateSession() error: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sess.ID.String(), nil)
	r.SetPathValue("id", sess.ID.String())

	// Inject user identity for ownership check
	rctx := context.WithValue(r.Context(), ctxKeyUserID, testOwnerID)
	r = r.WithContext(rctx)

	sm.deleteSession(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("deleteSession() status = %d, want %d\nbody: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]string
	decodeData(t, w, &resp)

	if resp["status"] != "deleted" {
		t.Errorf("deleteSession() status = %q, want %q", resp["status"], "deleted")
	}

	// Verify session is actually gone
	_, err = sm.store.Session(ctx, sess.ID)
	if err == nil {
		t.Error("deleteSession() session still exists after deletion")
	}
}

func TestCSRFTokenEndpoint_WithSession(t *testing.T) {
	sm := setupIntegrationSessionManager(t)

	userID := uuid.New().String()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)

	// Inject user identity into context (csrfToken handler reads from context now)
	ctx := context.WithValue(r.Context(), ctxKeyUserID, userID)
	r = r.WithContext(ctx)

	sm.csrfToken(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("csrfToken(with user) status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	decodeData(t, w, &body)

	token := body["csrfToken"]
	if token == "" {
		t.Fatal("csrfToken(with user) expected csrfToken in response")
	}

	// User-bound tokens should NOT have pre: prefix
	if isPreSessionToken(token) {
		t.Error("csrfToken(with user) should return user-bound token, not pre-session")
	}

	// Token should validate against the user
	if err := sm.CheckCSRF(userID, token); err != nil {
		t.Fatalf("csrfToken(with user) returned invalid token: %v", err)
	}
}

// TestMaybeGenerateTitle_SessionHasTitle verifies that maybeGenerateTitle
// returns empty when the session already has a title (no overwrite).
func TestMaybeGenerateTitle_SessionHasTitle(t *testing.T) {
	sm := setupIntegrationSessionManager(t)
	ctx := context.Background()

	sess, err := sm.store.CreateSession(ctx, testOwnerID, "Existing Title")
	if err != nil {
		t.Fatalf("setup: CreateSession() error: %v", err)
	}

	ch := &chatHandler{
		logger:   slog.New(slog.DiscardHandler),
		sessions: sm,
	}

	title := ch.maybeGenerateTitle(ctx, sess.ID.String(), "new message")
	if title != "" {
		t.Errorf("maybeGenerateTitle(%q) = %q, want empty string", sess.ID.String(), title)
	}
}

// TestMaybeGenerateTitle_FallbackTruncation verifies that when agent is nil,
// maybeGenerateTitle falls back to truncateForTitle for title generation.
func TestMaybeGenerateTitle_FallbackTruncation(t *testing.T) {
	sm := setupIntegrationSessionManager(t)
	ctx := context.Background()

	// Create session with empty title
	sess, err := sm.store.CreateSession(ctx, testOwnerID, "")
	if err != nil {
		t.Fatalf("setup: CreateSession() error: %v", err)
	}

	ch := &chatHandler{
		logger:   slog.New(slog.DiscardHandler),
		agent:    nil, // no AI title generation
		sessions: sm,
	}

	userMsg := "How do I use Go generics effectively?"
	title := ch.maybeGenerateTitle(ctx, sess.ID.String(), userMsg)

	if title == "" {
		t.Fatal("maybeGenerateTitle(fallback) = empty, want truncated title")
	}

	// Verify fallback matches truncateForTitle behavior
	want := truncateForTitle(userMsg)
	if title != want {
		t.Errorf("maybeGenerateTitle(%q) = %q, want %q", sess.ID.String(), title, want)
	}

	// Verify title was persisted
	updated, err := sm.store.Session(ctx, sess.ID)
	if err != nil {
		t.Fatalf("verifying title: %v", err)
	}
	if updated.Title != title {
		t.Errorf("persisted title = %q, want %q", updated.Title, title)
	}
}

func TestGetSessionMessages_WithMessages(t *testing.T) {
	sm := setupIntegrationSessionManager(t)
	ctx := context.Background()

	// Create a session with messages
	sess, err := sm.store.CreateSession(ctx, testOwnerID, "Test Chat")
	if err != nil {
		t.Fatalf("setup: CreateSession() error: %v", err)
	}

	// Add user and model messages
	msgs := []*ai.Message{
		ai.NewUserMessage(ai.NewTextPart("What is Go?")),
		ai.NewModelMessage(ai.NewTextPart("Go is a programming language.")),
	}
	if err := sm.store.AppendMessages(ctx, sess.ID, msgs); err != nil {
		t.Fatalf("setup: AppendMessages() error: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sess.ID.String()+"/messages", nil)
	r.SetPathValue("id", sess.ID.String())

	rctx := context.WithValue(r.Context(), ctxKeyUserID, testOwnerID)
	r = r.WithContext(rctx)

	sm.getSessionMessages(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("getSessionMessages() status = %d, want %d\nbody: %s", w.Code, http.StatusOK, w.Body.String())
	}

	type messageItem struct {
		ID        string `json:"id"`
		Role      string `json:"role"`
		Content   string `json:"content"`
		CreatedAt string `json:"createdAt"`
	}
	var body struct {
		Items []messageItem `json:"items"`
		Total int           `json:"total"`
	}
	decodeData(t, w, &body)

	if len(body.Items) != 2 {
		t.Fatalf("getSessionMessages() returned %d items, want 2", len(body.Items))
	}
	if body.Total != 2 {
		t.Errorf("getSessionMessages() total = %d, want 2", body.Total)
	}

	// First message: user
	if body.Items[0].Role != "user" {
		t.Errorf("getSessionMessages() items[0].role = %q, want %q", body.Items[0].Role, "user")
	}
	if body.Items[0].Content != "What is Go?" {
		t.Errorf("getSessionMessages() items[0].content = %q, want %q", body.Items[0].Content, "What is Go?")
	}
	if body.Items[0].ID == "" {
		t.Error("getSessionMessages() items[0].id is empty")
	}
	if body.Items[0].CreatedAt == "" {
		t.Error("getSessionMessages() items[0].createdAt is empty")
	}

	// Second message: model (normalizeRole converts "model" → "assistant" in DB)
	if body.Items[1].Role != "assistant" {
		t.Errorf("getSessionMessages() items[1].role = %q, want %q", body.Items[1].Role, "assistant")
	}
	if body.Items[1].Content != "Go is a programming language." {
		t.Errorf("getSessionMessages() items[1].content = %q, want %q", body.Items[1].Content, "Go is a programming language.")
	}
	if body.Items[1].ID == "" {
		t.Error("getSessionMessages() items[1].id is empty")
	}
}
