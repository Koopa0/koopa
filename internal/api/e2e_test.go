//go:build integration

package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/sqlc"
	"github.com/koopa0/koopa/internal/testutil"
)

// e2eServer creates a full Server with all middleware backed by a real PostgreSQL database.
// Returns the server handler and cleanup function.
func e2eServer(t *testing.T) http.Handler {
	t.Helper()

	db := testutil.SetupTestDB(t)

	store := session.New(sqlc.New(db.Pool), db.Pool, slog.New(slog.DiscardHandler))

	srv, err := NewServer(ServerConfig{
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

	preSessionToken := csrfResp["csrfToken"]
	if preSessionToken == "" {
		t.Fatal("step 1: expected csrfToken in response")
	}
	if !strings.HasPrefix(preSessionToken, "pre:") {
		t.Fatalf("step 1: token = %q, want pre: prefix", preSessionToken)
	}

	// --- Step 2: POST /api/v1/sessions with pre-session CSRF → 201 ---
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r2.RemoteAddr = "10.0.0.1:12345"
	r2.Header.Set("X-CSRF-Token", preSessionToken)

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

	// Extract cookies (should have sid cookie)
	cookies := e2eCookies(t, w2)
	var sidCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "sid" {
			sidCookie = c
		}
	}
	if sidCookie == nil {
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

	var getResp map[string]string
	decodeData(t, w3, &getResp)

	if getResp["id"] != sessionID {
		t.Errorf("step 3: id = %q, want %q", getResp["id"], sessionID)
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

	// Create session A
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)
	r1.RemoteAddr = "10.0.0.1:12345"
	handler.ServeHTTP(w1, r1)

	var csrf1 map[string]string
	decodeData(t, w1, &csrf1)

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r2.RemoteAddr = "10.0.0.1:12345"
	r2.Header.Set("X-CSRF-Token", csrf1["csrfToken"])
	handler.ServeHTTP(w2, r2)

	var sessA map[string]string
	decodeData(t, w2, &sessA)
	cookiesA := e2eCookies(t, w2)

	// Create session B (different "client")
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)
	r3.RemoteAddr = "10.0.0.2:12345"
	handler.ServeHTTP(w3, r3)

	var csrf2 map[string]string
	decodeData(t, w3, &csrf2)

	w4 := httptest.NewRecorder()
	r4 := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r4.RemoteAddr = "10.0.0.2:12345"
	r4.Header.Set("X-CSRF-Token", csrf2["csrfToken"])
	handler.ServeHTTP(w4, r4)

	var sessB map[string]string
	decodeData(t, w4, &sessB)

	// Client A tries to access session B → 403
	w5 := httptest.NewRecorder()
	r5 := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sessB["id"], nil)
	r5.RemoteAddr = "10.0.0.1:12345"
	e2eAddCookies(r5, cookiesA) // Cookie has session A

	handler.ServeHTTP(w5, r5)

	if w5.Code != http.StatusForbidden {
		t.Fatalf("cross-session GET status = %d, want %d", w5.Code, http.StatusForbidden)
	}

	errResp := decodeErrorEnvelope(t, w5)
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

	// --- Create a session first (ownership check requires valid cookie) ---
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/api/v1/csrf-token", nil)
	r1.RemoteAddr = "10.0.0.1:12345"
	handler.ServeHTTP(w1, r1)

	var csrfResp map[string]string
	decodeData(t, w1, &csrfResp)

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	r2.RemoteAddr = "10.0.0.1:12345"
	r2.Header.Set("X-CSRF-Token", csrfResp["csrfToken"])
	handler.ServeHTTP(w2, r2)

	if w2.Code != http.StatusCreated {
		t.Fatalf("create session status = %d, want %d\nbody: %s", w2.Code, http.StatusCreated, w2.Body.String())
	}

	var sessResp map[string]string
	decodeData(t, w2, &sessResp)
	sessionID := sessResp["id"]
	cookies := e2eCookies(t, w2)

	// --- SSE stream with valid session cookie ---
	// e2eServer has no ChatFlow configured (nil), so the handler returns
	// an error event instead of chunk/done events.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/chat/stream?msgId=e2e-1&session_id="+sessionID+"&query=hello", nil)
	r.RemoteAddr = "10.0.0.1:12345"
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
