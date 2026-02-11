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

// setupIntegrationSessionManager creates a sessionManager backed by a real PostgreSQL database.
func setupIntegrationSessionManager(t *testing.T) *sessionManager {
	t.Helper()

	db := testutil.SetupTestDB(t)

	store := session.New(sqlc.New(db.Pool), db.Pool, slog.New(slog.DiscardHandler))

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

	// Should return a CSRF token bound to the new session
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
	sess, err := sm.store.CreateSession(ctx, "Test Session")
	if err != nil {
		t.Fatalf("setup: CreateSession() error: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sess.ID.String(), nil)
	r.SetPathValue("id", sess.ID.String())

	// Inject session ownership (same session ID in context)
	rctx := context.WithValue(r.Context(), ctxKeySessionID, sess.ID)
	r = r.WithContext(rctx)

	sm.getSession(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("getSession(%s) status = %d, want %d\nbody: %s", sess.ID, w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]string
	decodeData(t, w, &resp)

	if resp["id"] != sess.ID.String() {
		t.Errorf("getSession() id = %q, want %q", resp["id"], sess.ID.String())
	}
	if resp["title"] != "Test Session" {
		t.Errorf("getSession() title = %q, want %q", resp["title"], "Test Session")
	}
	if resp["createdAt"] == "" {
		t.Error("getSession() expected createdAt in response")
	}
	if resp["updatedAt"] == "" {
		t.Error("getSession() expected updatedAt in response")
	}
}

func TestGetSession_NotFound(t *testing.T) {
	sm := setupIntegrationSessionManager(t)

	missingID := uuid.New()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+missingID.String(), nil)
	r.SetPathValue("id", missingID.String())

	// Set ownership to match (bypasses ownership check, tests store-level 404)
	rctx := context.WithValue(r.Context(), ctxKeySessionID, missingID)
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
	sess, err := sm.store.CreateSession(ctx, "My Chat")
	if err != nil {
		t.Fatalf("setup: CreateSession() error: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)

	// Inject session ownership
	rctx := context.WithValue(r.Context(), ctxKeySessionID, sess.ID)
	r = r.WithContext(rctx)

	sm.listSessions(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("listSessions() status = %d, want %d\nbody: %s", w.Code, http.StatusOK, w.Body.String())
	}

	type sessionItem struct {
		ID        string `json:"id"`
		Title     string `json:"title"`
		UpdatedAt string `json:"updatedAt"`
	}
	var items []sessionItem
	decodeData(t, w, &items)

	if len(items) != 1 {
		t.Fatalf("listSessions() returned %d items, want 1", len(items))
	}
	if items[0].ID != sess.ID.String() {
		t.Errorf("listSessions() items[0].id = %q, want %q", items[0].ID, sess.ID.String())
	}
	if items[0].Title != "My Chat" {
		t.Errorf("listSessions() items[0].title = %q, want %q", items[0].Title, "My Chat")
	}
	if items[0].UpdatedAt == "" {
		t.Error("listSessions() expected updatedAt in item")
	}
}

func TestGetSessionMessages_Empty(t *testing.T) {
	sm := setupIntegrationSessionManager(t)
	ctx := context.Background()

	// Create a session with no messages
	sess, err := sm.store.CreateSession(ctx, "")
	if err != nil {
		t.Fatalf("setup: CreateSession() error: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sess.ID.String()+"/messages", nil)
	r.SetPathValue("id", sess.ID.String())

	rctx := context.WithValue(r.Context(), ctxKeySessionID, sess.ID)
	r = r.WithContext(rctx)

	sm.getSessionMessages(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("getSessionMessages(empty) status = %d, want %d\nbody: %s", w.Code, http.StatusOK, w.Body.String())
	}

	// Decode the raw envelope to check the data type
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decoding envelope: %v", err)
	}

	var items []json.RawMessage
	if err := json.Unmarshal(env.Data, &items); err != nil {
		t.Fatalf("decoding data as array: %v", err)
	}

	if len(items) != 0 {
		t.Errorf("getSessionMessages(empty) returned %d items, want 0", len(items))
	}
}

func TestDeleteSession_Success(t *testing.T) {
	sm := setupIntegrationSessionManager(t)
	ctx := context.Background()

	// Create a session
	sess, err := sm.store.CreateSession(ctx, "To Delete")
	if err != nil {
		t.Fatalf("setup: CreateSession() error: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sess.ID.String(), nil)
	r.SetPathValue("id", sess.ID.String())

	// Inject ownership
	rctx := context.WithValue(r.Context(), ctxKeySessionID, sess.ID)
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
	ctx := context.Background()

	// Create a real session
	sess, err := sm.store.CreateSession(ctx, "")
	if err != nil {
		t.Fatalf("setup: CreateSession() error: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)
	r.AddCookie(&http.Cookie{
		Name:  "sid",
		Value: sess.ID.String(),
	})

	sm.csrfToken(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("csrfToken(with session) status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	decodeData(t, w, &body)

	token := body["csrfToken"]
	if token == "" {
		t.Fatal("csrfToken(with session) expected csrfToken in response")
	}

	// Session-bound tokens should NOT have pre: prefix
	if isPreSessionToken(token) {
		t.Error("csrfToken(with session) should return session-bound token, not pre-session")
	}

	// Token should validate against the session
	if err := sm.CheckCSRF(sess.ID, token); err != nil {
		t.Fatalf("csrfToken(with session) returned invalid token: %v", err)
	}
}

func TestGetSessionMessages_WithMessages(t *testing.T) {
	sm := setupIntegrationSessionManager(t)
	ctx := context.Background()

	// Create a session with messages
	sess, err := sm.store.CreateSession(ctx, "Test Chat")
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

	rctx := context.WithValue(r.Context(), ctxKeySessionID, sess.ID)
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
	var items []messageItem
	decodeData(t, w, &items)

	if len(items) != 2 {
		t.Fatalf("getSessionMessages() returned %d items, want 2", len(items))
	}

	// First message: user
	if items[0].Role != "user" {
		t.Errorf("getSessionMessages() items[0].role = %q, want %q", items[0].Role, "user")
	}
	if items[0].Content != "What is Go?" {
		t.Errorf("getSessionMessages() items[0].content = %q, want %q", items[0].Content, "What is Go?")
	}
	if items[0].ID == "" {
		t.Error("getSessionMessages() items[0].id is empty")
	}
	if items[0].CreatedAt == "" {
		t.Error("getSessionMessages() items[0].createdAt is empty")
	}

	// Second message: model (normalizeRole converts "model" → "assistant" in DB)
	if items[1].Role != "assistant" {
		t.Errorf("getSessionMessages() items[1].role = %q, want %q", items[1].Role, "assistant")
	}
	if items[1].Content != "Go is a programming language." {
		t.Errorf("getSessionMessages() items[1].content = %q, want %q", items[1].Content, "Go is a programming language.")
	}
	if items[1].ID == "" {
		t.Error("getSessionMessages() items[1].id is empty")
	}
}
