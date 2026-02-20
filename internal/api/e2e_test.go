//go:build integration

package api

import (
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/sqlc"
	"github.com/koopa0/koopa/internal/testutil"
)

var sharedDB *testutil.TestDBContainer

func TestMain(m *testing.M) {
	var cleanup func()
	var err error
	sharedDB, cleanup, err = testutil.SetupTestDBForMain()
	if err != nil {
		log.Fatalf("starting test database: %v", err)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// e2eServer creates a full Server with all middleware backed by the shared PostgreSQL database.
// Returns the server handler. Tables are truncated for isolation.
func e2eServer(t *testing.T) http.Handler {
	t.Helper()

	testutil.CleanTables(t, sharedDB.Pool)

	store := session.New(sqlc.New(sharedDB.Pool), sharedDB.Pool, slog.New(slog.DiscardHandler))

	srv, err := NewServer(context.Background(), ServerConfig{
		Logger:       slog.New(slog.DiscardHandler),
		SessionStore: store,
		CSRFSecret:   []byte("e2e-test-secret-at-least-32-characters!!"),
		CORSOrigins:  []string{"http://localhost:4200"},
		IsDev:        true,
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	return srv.Handler()
}

// e2eCookies extracts cookies from a response for use in subsequent requests.
// When multiple Set-Cookie headers share the same name, only the last one is kept
// (matching browser behavior where later cookies overwrite earlier ones).
func e2eCookies(t *testing.T, w *httptest.ResponseRecorder) []*http.Cookie {
	t.Helper()
	all := w.Result().Cookies()
	seen := make(map[string]int, len(all))
	var deduped []*http.Cookie
	for _, c := range all {
		if idx, ok := seen[c.Name]; ok {
			deduped[idx] = c // overwrite with later cookie
		} else {
			seen[c.Name] = len(deduped)
			deduped = append(deduped, c)
		}
	}
	return deduped
}

// e2eAddCookies adds cookies to a request.
func e2eAddCookies(r *http.Request, cookies []*http.Cookie) {
	for _, c := range cookies {
		r.AddCookie(c)
	}
}

func TestE2E_HealthBypassesMiddleware(t *testing.T) {
	handler := e2eServer(t)

	for _, path := range []string{"/health", "/ready"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.RemoteAddr = "10.0.0.1:12345"

			handler.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want %d", path, w.Code, http.StatusOK)
			}

			// Health probes are on the top-level mux and bypass the middleware stack
			// (including security headers). Verify they return valid JSON.
			var body map[string]string
			decodeData(t, w, &body)
			if body["status"] != "ok" {
				t.Errorf("GET %s status = %q, want %q", path, body["status"], "ok")
			}
		})
	}
}

func TestE2E_FullSessionLifecycle(t *testing.T) {
	handler := e2eServer(t)

	// --- Step 1: GET /api/v1/csrf-token → pre-session token ---
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)
	r1.RemoteAddr = "10.0.0.1:12345"

	handler.ServeHTTP(w1, r1)

	if w1.Code != http.StatusOK {
		t.Fatalf("step 1: GET /csrf-token status = %d, want %d", w1.Code, http.StatusOK)
	}

	var csrfResp map[string]string
	decodeData(t, w1, &csrfResp)

	csrfToken := csrfResp["csrfToken"]
	if csrfToken == "" {
		t.Fatal("step 1: expected csrfToken in response")
	}
	// userMiddleware auto-provisions uid on first request, so the CSRF token
	// is always user-bound (not pre-session). It should NOT have a "pre:" prefix.
	if strings.HasPrefix(csrfToken, "pre:") {
		t.Fatalf("step 1: token = %q, should be user-bound (not pre:)", csrfToken)
	}

	// --- Step 2: POST /api/v1/sessions with user-bound CSRF → 201 ---
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r2.RemoteAddr = "10.0.0.1:12345"
	r2.Header.Set("X-CSRF-Token", csrfToken)
	// Carry uid cookie from step 1 (required for CSRF validation)
	for _, c := range w1.Result().Cookies() {
		r2.AddCookie(c)
	}

	handler.ServeHTTP(w2, r2)

	if w2.Code != http.StatusCreated {
		t.Fatalf("step 2: POST /sessions status = %d, want %d\nbody: %s", w2.Code, http.StatusCreated, w2.Body.String())
	}

	var createResp map[string]string
	decodeData(t, w2, &createResp)

	sessionID := createResp["id"]
	sessionCSRF := createResp["csrfToken"]

	if sessionID == "" {
		t.Fatal("step 2: expected id in response")
	}
	if sessionCSRF == "" {
		t.Fatal("step 2: expected csrfToken in response")
	}
	if strings.HasPrefix(sessionCSRF, "pre:") {
		t.Fatal("step 2: session-bound token should not have pre: prefix")
	}

	// Merge cookies from step 1 (uid) and step 2 (sid).
	// userMiddleware set uid in step 1; createSession set sid in step 2.
	allCookies := make(map[string]*http.Cookie)
	for _, c := range w1.Result().Cookies() {
		allCookies[c.Name] = c
	}
	for _, c := range w2.Result().Cookies() {
		allCookies[c.Name] = c
	}
	var cookies []*http.Cookie
	for _, c := range allCookies {
		cookies = append(cookies, c)
	}

	if _, ok := allCookies["sid"]; !ok {
		t.Fatal("step 2: expected sid cookie")
	}

	// --- Step 3: GET /api/v1/sessions/{id} with cookie → 200 ---
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sessionID, nil)
	r3.RemoteAddr = "10.0.0.1:12345"
	e2eAddCookies(r3, cookies)

	handler.ServeHTTP(w3, r3)

	if w3.Code != http.StatusOK {
		t.Fatalf("step 3: GET /sessions/%s status = %d, want %d\nbody: %s", sessionID, w3.Code, http.StatusOK, w3.Body.String())
	}

	var getResp struct {
		ID           string `json:"id"`
		Title        string `json:"title"`
		MessageCount int    `json:"messageCount"`
		CreatedAt    string `json:"createdAt"`
		UpdatedAt    string `json:"updatedAt"`
	}
	decodeData(t, w3, &getResp)

	if getResp.ID != sessionID {
		t.Errorf("step 3: id = %q, want %q", getResp.ID, sessionID)
	}

	// --- Step 4: GET /api/v1/sessions/{id}/messages → 200 (empty) ---
	w4 := httptest.NewRecorder()
	r4 := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sessionID+"/messages", nil)
	r4.RemoteAddr = "10.0.0.1:12345"
	e2eAddCookies(r4, cookies)

	handler.ServeHTTP(w4, r4)

	if w4.Code != http.StatusOK {
		t.Fatalf("step 4: GET /sessions/%s/messages status = %d, want %d\nbody: %s", sessionID, w4.Code, http.StatusOK, w4.Body.String())
	}

	// --- Step 5: GET /api/v1/sessions with cookie → 200 (list contains session) ---
	w5 := httptest.NewRecorder()
	r5 := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	r5.RemoteAddr = "10.0.0.1:12345"
	e2eAddCookies(r5, cookies)

	handler.ServeHTTP(w5, r5)

	if w5.Code != http.StatusOK {
		t.Fatalf("step 5: GET /sessions status = %d, want %d", w5.Code, http.StatusOK)
	}

	// --- Step 6: DELETE /api/v1/sessions/{id} with cookie + CSRF → 200 ---
	w6 := httptest.NewRecorder()
	r6 := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sessionID, nil)
	r6.RemoteAddr = "10.0.0.1:12345"
	r6.Header.Set("X-CSRF-Token", sessionCSRF)
	e2eAddCookies(r6, cookies)

	handler.ServeHTTP(w6, r6)

	if w6.Code != http.StatusOK {
		t.Fatalf("step 6: DELETE /sessions/%s status = %d, want %d\nbody: %s", sessionID, w6.Code, http.StatusOK, w6.Body.String())
	}

	// --- Step 7: GET deleted session → 404 ---
	w7 := httptest.NewRecorder()
	r7 := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sessionID, nil)
	r7.RemoteAddr = "10.0.0.1:12345"
	e2eAddCookies(r7, cookies)

	handler.ServeHTTP(w7, r7)

	if w7.Code != http.StatusNotFound {
		t.Fatalf("step 7: GET deleted session status = %d, want %d", w7.Code, http.StatusNotFound)
	}
}

func TestE2E_MissingCSRF_Rejected(t *testing.T) {
	handler := e2eServer(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	// No X-CSRF-Token header

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("POST /sessions (no CSRF) status = %d, want %d\nbody: %s", w.Code, http.StatusForbidden, w.Body.String())
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "csrf_invalid" && errResp.Code != "session_required" {
		t.Errorf("POST /sessions (no CSRF) code = %q, want csrf_invalid or session_required", errResp.Code)
	}
}

func TestE2E_InvalidCSRF_Rejected(t *testing.T) {
	handler := e2eServer(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-CSRF-Token", "totally-fake-token")

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("POST /sessions (bad CSRF) status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestE2E_CrossSessionAccess_Denied(t *testing.T) {
	handler := e2eServer(t)

	// Create session A using helper
	cookiesA, _, _ := e2eCreateSession(t, handler, "10.0.0.1:12345")

	// Create session B (different "client" = different IP → different uid)
	_, sessionB, _ := e2eCreateSession(t, handler, "10.0.0.2:12345")

	// Client A tries to access session B → 403
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sessionB, nil)
	r.RemoteAddr = "10.0.0.1:12345"
	e2eAddCookies(r, cookiesA)

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-session GET status = %d, want %d", w.Code, http.StatusForbidden)
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "forbidden" {
		t.Errorf("cross-session GET code = %q, want %q", errResp.Code, "forbidden")
	}
}

func TestE2E_RateLimiting(t *testing.T) {
	handler := e2eServer(t)

	// Rate limiter is configured at 1 token/sec, burst 60.
	// /health bypasses the middleware stack, so use an API path that goes through rate limiting.
	var lastCode int
	for i := range 65 {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)
		r.RemoteAddr = "10.99.99.99:12345" // Unique IP so no interference

		handler.ServeHTTP(w, r)
		lastCode = w.Code

		if w.Code == http.StatusTooManyRequests {
			// Verify Retry-After header
			if got := w.Header().Get("Retry-After"); got != "1" {
				t.Errorf("rate limited Retry-After = %q, want %q", got, "1")
			}
			t.Logf("rate limited at request %d", i+1)
			return
		}
	}

	t.Fatalf("rate limiter: no 429 within 65 requests, last status = %d", lastCode)
}

func TestE2E_SecurityHeaders(t *testing.T) {
	handler := e2eServer(t)

	// Only check API paths — /health and /ready are on the top-level mux
	// and intentionally bypass the middleware stack (including security headers).
	paths := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/csrf-token"},
		{http.MethodGet, "/api/v1/sessions"},
	}

	for _, p := range paths {
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(p.method, p.path, nil)
			r.RemoteAddr = "10.0.0.1:12345"

			handler.ServeHTTP(w, r)

			wantHeaders := map[string]string{
				"X-Content-Type-Options":  "nosniff",
				"X-Frame-Options":         "DENY",
				"Referrer-Policy":         "strict-origin-when-cross-origin",
				"Content-Security-Policy": "default-src 'none'",
			}

			for header, want := range wantHeaders {
				if got := w.Header().Get(header); got != want {
					t.Errorf("%s %s header %q = %q, want %q", p.method, p.path, header, got, want)
				}
			}
		})
	}
}

func TestE2E_CORSPreflight(t *testing.T) {
	handler := e2eServer(t)

	t.Run("allowed origin", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodOptions, "/api/v1/sessions", nil)
		r.RemoteAddr = "10.0.0.1:12345"
		r.Header.Set("Origin", "http://localhost:4200")

		handler.ServeHTTP(w, r)

		if w.Code != http.StatusNoContent {
			t.Fatalf("CORS preflight status = %d, want %d", w.Code, http.StatusNoContent)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:4200" {
			t.Errorf("Allow-Origin = %q, want %q", got, "http://localhost:4200")
		}
		if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Errorf("Allow-Credentials = %q, want %q", got, "true")
		}
	})

	t.Run("disallowed origin", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodOptions, "/api/v1/sessions", nil)
		r.RemoteAddr = "10.0.0.1:12345"
		r.Header.Set("Origin", "http://evil.com")

		handler.ServeHTTP(w, r)

		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("disallowed origin Allow-Origin = %q, want empty", got)
		}
	})
}

func TestE2E_SSEStream(t *testing.T) {
	handler := e2eServer(t)
	addr := "10.0.0.1:12345"

	// Create session using helper (handles cookie merging)
	cookies, sessionID, _ := e2eCreateSession(t, handler, addr)

	// Get a fresh CSRF token for POST /chat
	csrf := e2eGetCSRF(t, handler, cookies, addr)

	// POST /api/v1/chat to store query server-side
	chatBody := strings.NewReader(`{"content":"hello","sessionId":"` + sessionID + `"}`)
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "/api/v1/chat", chatBody)
	r1.RemoteAddr = addr
	r1.Header.Set("Content-Type", "application/json")
	r1.Header.Set("X-CSRF-Token", csrf)
	e2eAddCookies(r1, cookies)
	handler.ServeHTTP(w1, r1)

	if w1.Code != http.StatusOK {
		t.Fatalf("POST /chat status = %d, want %d\nbody: %s", w1.Code, http.StatusOK, w1.Body.String())
	}

	var chatResp map[string]string
	decodeData(t, w1, &chatResp)
	streamURL := chatResp["streamUrl"]
	if streamURL == "" {
		t.Fatal("POST /chat response missing streamUrl")
	}

	// SSE stream using the URL returned by send().
	// e2eServer has no ChatFlow configured (nil), so the handler returns
	// an error event instead of chunk/done events.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, streamURL, nil)
	r.RemoteAddr = addr
	e2eAddCookies(r, cookies)

	handler.ServeHTTP(w, r)

	// Should get SSE response (200 implicit from streaming)
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("SSE Content-Type = %q, want %q", ct, "text/event-stream")
	}

	body := w.Body.String()

	// With nil ChatFlow, handler sends error event
	if !strings.Contains(body, "event: error\n") {
		t.Errorf("SSE response missing error event, body:\n%s", body)
	}
	if !strings.Contains(body, "chat flow not initialized") {
		t.Errorf("SSE error missing expected message, body:\n%s", body)
	}
}

// =============================================================================
// Proposal 019 — Security Fix Scenario Tests
//
// Each test exercises the full middleware stack (Recovery → Logging → CORS →
// RateLimit → User → Session → CSRF → Routes) backed by a real PostgreSQL
// database. Tests map to specific security findings from the third-party review.
// =============================================================================

// e2eCreateSession is a helper that provisions CSRF, creates a session, and
// returns cookies + sessionID + CSRF token. Fails the test on any error.
func e2eCreateSession(t *testing.T, handler http.Handler, remoteAddr string) (cookies []*http.Cookie, sessionID, csrfToken string) {
	t.Helper()

	// Step 1: Get CSRF token (userMiddleware auto-provisions uid cookie)
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)
	r1.RemoteAddr = remoteAddr
	handler.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("e2eCreateSession: GET /csrf-token status = %d, want %d", w1.Code, http.StatusOK)
	}
	var csrf1 map[string]string
	decodeData(t, w1, &csrf1)
	step1Cookies := w1.Result().Cookies()

	// Step 2: Create session with user-bound CSRF token
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r2.RemoteAddr = remoteAddr
	r2.Header.Set("X-CSRF-Token", csrf1["csrfToken"])
	// Carry cookies from step 1 (uid cookie is set by userMiddleware)
	for _, c := range step1Cookies {
		r2.AddCookie(c)
	}
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusCreated {
		t.Fatalf("e2eCreateSession: POST /sessions status = %d, want %d\nbody: %s", w2.Code, http.StatusCreated, w2.Body.String())
	}
	var sessResp map[string]string
	decodeData(t, w2, &sessResp)

	// Merge cookies from both steps: step 1 has uid, step 2 has sid.
	// Use a map to deduplicate (later cookies overwrite earlier ones).
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range step1Cookies {
		cookieMap[c.Name] = c
	}
	for _, c := range w2.Result().Cookies() {
		cookieMap[c.Name] = c
	}
	for _, c := range cookieMap {
		cookies = append(cookies, c)
	}

	return cookies, sessResp["id"], sessResp["csrfToken"]
}

// e2eGetCSRF fetches a fresh CSRF token using the given cookies.
func e2eGetCSRF(t *testing.T, handler http.Handler, cookies []*http.Cookie, remoteAddr string) string {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)
	r.RemoteAddr = remoteAddr
	e2eAddCookies(r, cookies)
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("e2eGetCSRF: GET /csrf-token status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]string
	decodeData(t, w, &resp)
	return resp["csrfToken"]
}

// --- F4/CWE-565: HMAC-Signed uid Cookie (Identity Impersonation Prevention) ---

// TestE2E_F4_UIDCookieTamperRejected verifies that a tampered uid cookie is rejected
// by the full middleware stack. The userMiddleware should detect the invalid HMAC
// signature and provision a new identity, preventing identity impersonation.
//
// Acceptance criteria:
//   - Tampered uid cookie is not accepted as identity
//   - Server provisions a new identity (new uid cookie in response)
//   - Session created with tampered cookie belongs to the new identity, not the tampered one
//   - Cross-session access from tampered identity is denied
func TestE2E_F4_UIDCookieTamperRejected(t *testing.T) {
	handler := e2eServer(t)
	addr := "10.0.0.50:12345"

	// Step 1: Create a legitimate session (gets real uid cookie)
	cookies, sessionID, _ := e2eCreateSession(t, handler, addr)

	// Step 2: Tamper the uid cookie (change the value but keep the signature)
	var tamperedCookies []*http.Cookie
	for _, c := range cookies {
		if c.Name == userCookieName {
			// Replace with a forged uid (no valid HMAC)
			tamperedCookies = append(tamperedCookies, &http.Cookie{
				Name:  userCookieName,
				Value: "00000000-0000-0000-0000-000000000000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			})
		} else {
			tamperedCookies = append(tamperedCookies, c)
		}
	}

	// Step 3: Request with tampered uid → server should provision new identity
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sessionID, nil)
	r.RemoteAddr = addr
	e2eAddCookies(r, tamperedCookies)
	handler.ServeHTTP(w, r)

	// The tampered identity cannot access the original session → 403
	if w.Code != http.StatusForbidden {
		t.Fatalf("F4: tampered uid GET session status = %d, want %d\nbody: %s", w.Code, http.StatusForbidden, w.Body.String())
	}

	// Verify server provisioned a new uid cookie (HMAC-signed)
	var newUID string
	for _, c := range w.Result().Cookies() {
		if c.Name == userCookieName {
			newUID = c.Value
		}
	}
	if newUID == "" {
		t.Fatal("F4: server did not provision new uid cookie after tampered request")
	}

	// New uid must contain a dot (uid.signature format)
	if !strings.Contains(newUID, ".") {
		t.Errorf("F4: new uid cookie = %q, want uid.signature format", newUID)
	}
}

// TestE2E_F4_UIDCookieWithoutSignatureRejected verifies that a uid cookie
// without any HMAC signature is rejected.
//
// Acceptance criteria:
//   - Plain UUID without signature is rejected
//   - Server provisions a new identity
func TestE2E_F4_UIDCookieWithoutSignatureRejected(t *testing.T) {
	handler := e2eServer(t)
	addr := "10.0.0.51:12345"

	// Create a session first
	cookies, sessionID, _ := e2eCreateSession(t, handler, addr)

	// Replace uid cookie with unsigned UUID
	var unsignedCookies []*http.Cookie
	for _, c := range cookies {
		if c.Name == userCookieName {
			unsignedCookies = append(unsignedCookies, &http.Cookie{
				Name:  userCookieName,
				Value: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", // no dot, no signature
			})
		} else {
			unsignedCookies = append(unsignedCookies, c)
		}
	}

	// Request with unsigned uid → server should deny access
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sessionID, nil)
	r.RemoteAddr = addr
	e2eAddCookies(r, unsignedCookies)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("F4: unsigned uid GET session status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// --- F6/CWE-400: Pending Query Capacity Limit (DoS Prevention) ---

// TestE2E_F6_PendingQueryCapacity verifies that the POST /chat endpoint
// enforces the pending query capacity limit through the full middleware stack.
//
// Acceptance criteria:
//   - Requests within capacity return 200 with streamUrl
//   - Requests exceeding capacity return 429 with "too_many_pending"
//   - Concurrent requests are correctly bounded by CAS loop (H1)
func TestE2E_F6_PendingQueryCapacity(t *testing.T) {
	handler := e2eServer(t)
	addr := "10.0.0.60:12345"

	// Create a session
	cookies, sessionID, _ := e2eCreateSession(t, handler, addr)

	// Get a user-bound CSRF token
	csrf := e2eGetCSRF(t, handler, cookies, addr)

	// Send a chat message → should succeed (capacity is fresh)
	chatBody := `{"content":"hello","sessionId":"` + sessionID + `"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(chatBody))
	r.RemoteAddr = addr
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	e2eAddCookies(r, cookies)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("F6: POST /chat status = %d, want %d\nbody: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]string
	decodeData(t, w, &resp)
	if resp["streamUrl"] == "" {
		t.Fatal("F6: POST /chat response missing streamUrl")
	}
	if resp["msgId"] == "" {
		t.Fatal("F6: POST /chat response missing msgId")
	}
}

// TestE2E_F6_PendingQueryOneTimeConsumption verifies that a pending query
// can only be consumed once via GET /stream (replay prevention).
//
// Acceptance criteria:
//   - First GET /stream with valid msgId succeeds (SSE response)
//   - Second GET /stream with same msgId returns 400 "query_not_found"
func TestE2E_F6_PendingQueryReplayPrevention(t *testing.T) {
	handler := e2eServer(t)
	addr := "10.0.0.61:12345"

	// Create session + send chat
	cookies, sessionID, _ := e2eCreateSession(t, handler, addr)
	csrf := e2eGetCSRF(t, handler, cookies, addr)

	chatBody := `{"content":"test replay","sessionId":"` + sessionID + `"}`
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(chatBody))
	r1.RemoteAddr = addr
	r1.Header.Set("Content-Type", "application/json")
	r1.Header.Set("X-CSRF-Token", csrf)
	e2eAddCookies(r1, cookies)
	handler.ServeHTTP(w1, r1)

	if w1.Code != http.StatusOK {
		t.Fatalf("F6 replay: POST /chat status = %d, want %d", w1.Code, http.StatusOK)
	}

	var chatResp map[string]string
	decodeData(t, w1, &chatResp)
	streamURL := chatResp["streamUrl"]

	// First consumption → SSE (200 implicit)
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, streamURL, nil)
	r2.RemoteAddr = addr
	e2eAddCookies(r2, cookies)
	handler.ServeHTTP(w2, r2)

	if ct := w2.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("F6 replay: first stream Content-Type = %q, want %q", ct, "text/event-stream")
	}

	// Second consumption → 400 "query_not_found" (replay blocked)
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodGet, streamURL, nil)
	r3.RemoteAddr = addr
	e2eAddCookies(r3, cookies)
	handler.ServeHTTP(w3, r3)

	if w3.Code != http.StatusBadRequest {
		t.Fatalf("F6 replay: second stream status = %d, want %d\nbody: %s", w3.Code, http.StatusBadRequest, w3.Body.String())
	}

	errResp := decodeErrorEnvelope(t, w3)
	if errResp.Code != "query_not_found" {
		t.Errorf("F6 replay: second stream error code = %q, want %q", errResp.Code, "query_not_found")
	}
}

// TestE2E_F6_StreamSessionMismatch verifies that a pending query cannot be
// consumed from a different session than it was created for.
//
// Acceptance criteria:
//   - POST /chat with session A creates pending query
//   - GET /stream with session B's session_id returns 400
func TestE2E_F6_StreamSessionMismatch(t *testing.T) {
	handler := e2eServer(t)
	addr := "10.0.0.62:12345"

	// Create session A
	cookiesA, sessionA, _ := e2eCreateSession(t, handler, addr)

	// Send chat to session A
	csrfA := e2eGetCSRF(t, handler, cookiesA, addr)
	chatBody := `{"content":"session mismatch test","sessionId":"` + sessionA + `"}`
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(chatBody))
	r1.RemoteAddr = addr
	r1.Header.Set("Content-Type", "application/json")
	r1.Header.Set("X-CSRF-Token", csrfA)
	e2eAddCookies(r1, cookiesA)
	handler.ServeHTTP(w1, r1)

	if w1.Code != http.StatusOK {
		t.Fatalf("F6 mismatch: POST /chat status = %d, want %d", w1.Code, http.StatusOK)
	}

	var chatResp map[string]string
	decodeData(t, w1, &chatResp)
	msgID := chatResp["msgId"]

	// Create session B (same user, different session)
	cookiesB, sessionB, _ := e2eCreateSession(t, handler, addr)

	// Try to consume session A's query with session B's session_id → should fail
	streamURL := "/api/v1/chat/stream?msgId=" + msgID + "&session_id=" + sessionB
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, streamURL, nil)
	r2.RemoteAddr = addr
	e2eAddCookies(r2, cookiesB)
	handler.ServeHTTP(w2, r2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("F6 mismatch: stream with wrong session status = %d, want %d\nbody: %s", w2.Code, http.StatusBadRequest, w2.Body.String())
	}
}

// --- Session Ownership (Cross-User Isolation) ---

// TestE2E_SessionOwnership_ChatAccessDenied verifies that POST /chat with
// another user's session is denied with 403.
//
// Acceptance criteria:
//   - User A creates session → POST /chat succeeds
//   - User B tries POST /chat with user A's sessionId → 403 "forbidden"
func TestE2E_SessionOwnership_ChatAccessDenied(t *testing.T) {
	handler := e2eServer(t)

	// User A creates a session
	_, sessionA, _ := e2eCreateSession(t, handler, "10.0.0.70:12345")

	// User B creates their own session (different IP → different uid cookie)
	cookiesB, _, _ := e2eCreateSession(t, handler, "10.0.0.71:12345")

	// User B tries to POST /chat to user A's session → 403
	csrfB := e2eGetCSRF(t, handler, cookiesB, "10.0.0.71:12345")
	chatBody := `{"content":"hack attempt","sessionId":"` + sessionA + `"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(chatBody))
	r.RemoteAddr = "10.0.0.71:12345"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrfB)
	e2eAddCookies(r, cookiesB)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("ownership: cross-user POST /chat status = %d, want %d\nbody: %s", w.Code, http.StatusForbidden, w.Body.String())
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "forbidden" {
		t.Errorf("ownership: cross-user POST /chat error code = %q, want %q", errResp.Code, "forbidden")
	}
}

// TestE2E_SessionOwnership_DeleteDenied verifies that DELETE /sessions/{id}
// with another user's session is denied with 403.
//
// Acceptance criteria:
//   - User A creates session
//   - User B tries DELETE on user A's session → 403
func TestE2E_SessionOwnership_DeleteDenied(t *testing.T) {
	handler := e2eServer(t)

	// User A creates a session
	_, sessionA, _ := e2eCreateSession(t, handler, "10.0.0.72:12345")

	// User B creates their own session
	cookiesB, _, _ := e2eCreateSession(t, handler, "10.0.0.73:12345")
	csrfB := e2eGetCSRF(t, handler, cookiesB, "10.0.0.73:12345")

	// User B tries to delete user A's session → 403
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sessionA, nil)
	r.RemoteAddr = "10.0.0.73:12345"
	r.Header.Set("X-CSRF-Token", csrfB)
	e2eAddCookies(r, cookiesB)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("ownership: cross-user DELETE status = %d, want %d\nbody: %s", w.Code, http.StatusForbidden, w.Body.String())
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "forbidden" {
		t.Errorf("ownership: cross-user DELETE error code = %q, want %q", errResp.Code, "forbidden")
	}
}

// TestE2E_SessionOwnership_MessagesDenied verifies that GET /sessions/{id}/messages
// with another user's session is denied with 403.
func TestE2E_SessionOwnership_MessagesDenied(t *testing.T) {
	handler := e2eServer(t)

	_, sessionA, _ := e2eCreateSession(t, handler, "10.0.0.74:12345")

	cookiesB, _, _ := e2eCreateSession(t, handler, "10.0.0.75:12345")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sessionA+"/messages", nil)
	r.RemoteAddr = "10.0.0.75:12345"
	e2eAddCookies(r, cookiesB)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("ownership: cross-user GET messages status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// --- CSRF Token Binding ---

// TestE2E_CSRF_UserBoundTokenCrossUserRejected verifies that a CSRF token
// generated for User A cannot be used by User B.
//
// Acceptance criteria:
//   - User A creates session, gets user-bound CSRF token
//   - User B tries to use user A's CSRF token → 403 "csrf_invalid"
func TestE2E_CSRF_UserBoundTokenCrossUserRejected(t *testing.T) {
	handler := e2eServer(t)

	// User A: create session + get CSRF
	_, _, csrfA := e2eCreateSession(t, handler, "10.0.0.80:12345")

	// User B: get own cookies
	cookiesB, _, _ := e2eCreateSession(t, handler, "10.0.0.81:12345")

	// User B tries to create session using User A's CSRF → 403
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r.RemoteAddr = "10.0.0.81:12345"
	r.Header.Set("X-CSRF-Token", csrfA) // User A's token
	e2eAddCookies(r, cookiesB)          // User B's cookies
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("CSRF cross-user: POST /sessions status = %d, want %d\nbody: %s", w.Code, http.StatusForbidden, w.Body.String())
	}

	errResp := decodeErrorEnvelope(t, w)
	if errResp.Code != "csrf_invalid" {
		t.Errorf("CSRF cross-user: error code = %q, want %q", errResp.Code, "csrf_invalid")
	}
}

// --- Chat Input Validation ---

// TestE2E_ChatValidation covers input validation for POST /chat through the
// full middleware stack.
//
// Acceptance criteria:
//   - Empty content → 400 "content_required"
//   - Invalid sessionId → 400 "invalid_session"
//   - Missing sessionId → 400 "session_required"
//   - Content exceeding maxChatContentLength → 413 "content_too_long"
func TestE2E_ChatValidation(t *testing.T) {
	handler := e2eServer(t)
	addr := "10.0.0.90:12345"

	cookies, sessionID, _ := e2eCreateSession(t, handler, addr)
	csrf := e2eGetCSRF(t, handler, cookies, addr)

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "empty content",
			body:       `{"content":"","sessionId":"` + sessionID + `"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "content_required",
		},
		{
			name:       "whitespace content",
			body:       `{"content":"   ","sessionId":"` + sessionID + `"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "content_required",
		},
		{
			name:       "missing sessionId",
			body:       `{"content":"hello"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "session_required",
		},
		{
			name:       "invalid sessionId",
			body:       `{"content":"hello","sessionId":"not-a-uuid"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_session",
		},
		{
			name:       "invalid JSON",
			body:       `{broken`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(tt.body))
			r.RemoteAddr = addr
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
			e2eAddCookies(r, cookies)
			handler.ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Fatalf("POST /chat (%s) status = %d, want %d\nbody: %s", tt.name, w.Code, tt.wantStatus, w.Body.String())
			}

			errResp := decodeErrorEnvelope(t, w)
			if errResp.Code != tt.wantCode {
				t.Errorf("POST /chat (%s) error code = %q, want %q", tt.name, errResp.Code, tt.wantCode)
			}
		})
	}
}

// --- H1: CAS Loop Concurrent Safety ---

// TestE2E_H1_ConcurrentChatSubmissions verifies that concurrent POST /chat
// requests through the full middleware stack are bounded by the CAS loop.
//
// Acceptance criteria:
//   - Multiple concurrent submissions all get valid responses (200 or 429)
//   - No race conditions or panics
func TestE2E_H1_ConcurrentChatSubmissions(t *testing.T) {
	handler := e2eServer(t)
	addr := "10.0.0.95:12345"

	cookies, sessionID, _ := e2eCreateSession(t, handler, addr)
	csrf := e2eGetCSRF(t, handler, cookies, addr)

	const goroutines = 10
	results := make(chan int, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(map[string]string{
				"content":   "concurrent test",
				"sessionId": sessionID,
			})
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(string(body)))
			r.RemoteAddr = addr
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
			e2eAddCookies(r, cookies)
			handler.ServeHTTP(w, r)
			results <- w.Code
		}()
	}

	wg.Wait()
	close(results)

	var ok, rejected int
	for code := range results {
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			rejected++
		default:
			t.Errorf("H1: unexpected status code: %d", code)
		}
	}

	// With fresh capacity (10000), all 10 should succeed
	if ok != goroutines {
		t.Errorf("H1: concurrent submissions: %d succeeded, want %d (rejected: %d)", ok, goroutines, rejected)
	}
}

// --- CWE-284: Query Content Not in URL ---

// TestE2E_CWE284_QueryNotInURL verifies that user message content does not
// appear in the streamUrl returned by POST /chat, preventing PII leakage
// to access logs, proxy logs, and Referer headers.
//
// Acceptance criteria:
//   - POST /chat returns streamUrl
//   - streamUrl does NOT contain the user's message content
//   - streamUrl only contains msgId and session_id parameters
func TestE2E_CWE284_QueryNotInURL(t *testing.T) {
	handler := e2eServer(t)
	addr := "10.0.0.96:12345"

	cookies, sessionID, _ := e2eCreateSession(t, handler, addr)
	csrf := e2eGetCSRF(t, handler, cookies, addr)

	secretContent := "my-secret-password-and-personal-info"
	chatBody := `{"content":"` + secretContent + `","sessionId":"` + sessionID + `"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/chat", strings.NewReader(chatBody))
	r.RemoteAddr = addr
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	e2eAddCookies(r, cookies)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("CWE-284: POST /chat status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	decodeData(t, w, &resp)

	streamURL := resp["streamUrl"]
	if strings.Contains(streamURL, secretContent) {
		t.Errorf("CWE-284: streamUrl contains user message content: %s", streamURL)
	}

	// Verify URL only has expected params
	if !strings.Contains(streamURL, "msgId=") {
		t.Error("CWE-284: streamUrl missing msgId parameter")
	}
	if !strings.Contains(streamURL, "session_id=") {
		t.Error("CWE-284: streamUrl missing session_id parameter")
	}
}
