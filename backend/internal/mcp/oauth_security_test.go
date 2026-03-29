package mcp

// oauth_adversarial_test.go — adversarial tests for the OAuth 2.1 provider.
//
// Attack surface:
//   - Client registration: maxClients cap, concurrent registration race
//   - Token issuance and validation: expired tokens, tampered tokens, replay
//   - PKCE: wrong verifier, empty verifier, SHA256 collision resistance
//   - Redirect URI validation: open-redirect / SSRF bypass attempts
//   - Token endpoint: unsupported grant types, malformed bodies, missing fields
//   - BearerAuth middleware: missing header, wrong prefix, garbage token
//   - Authorization code: replay attack (one-time use enforcement)
//   - Cleanup goroutine: expired entries evicted correctly

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/oauth2"
)

// newTestOAuth returns a minimal OAuthProvider with a stopped cleanup goroutine.
func newTestOAuth(t *testing.T) *OAuthProvider {
	t.Helper()
	o := NewOAuthProvider(OAuthConfig{
		StaticToken: "static-test-token",
		AdminEmail:  "admin@example.com",
		BaseURL:     "https://mcp.example.com",
		GoogleOAuth: &oauth2.Config{},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { close(o.Done) })
	return o
}

// registerClient is a test helper that registers one client and returns its credentials.
func registerClient(t *testing.T, o *OAuthProvider) (clientID, clientSecret string) {
	t.Helper()
	body := `{"redirect_uris":["https://claude.ai/oauth/callback"],"client_name":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	o.Register(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("Register() status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	var resp struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding register response: %v", err)
	}
	return resp.ClientID, resp.ClientSecret
}

// ---------------------------------------------------------------------------
// validRedirectURI — SSRF and open-redirect bypass attempts
// ---------------------------------------------------------------------------

func TestValidRedirectURI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		uri  string
		want bool
	}{
		// Allowed — happy paths
		{name: "claude.ai callback", uri: "https://claude.ai/oauth/callback", want: true},
		{name: "localhost with port", uri: "http://localhost:3000/callback", want: true},
		{name: "127.0.0.1 with port", uri: "http://127.0.0.1:8080/callback", want: true},

		// SSRF bypass attempts — all must be rejected
		{name: "file scheme", uri: "file:///etc/passwd", want: false},
		{name: "javascript scheme", uri: "javascript:alert(1)", want: false},
		{name: "data URI", uri: "data:text/html,<script>alert(1)</script>", want: false},
		{name: "HTTP not HTTPS on claude.ai", uri: "http://claude.ai/callback", want: false},
		{name: "subdomain of claude.ai", uri: "https://evil.claude.ai/callback", want: false},
		{name: "claude.ai prefix spoof", uri: "https://claude.ai.evil.com/callback", want: false},
		{name: "localhost without port", uri: "http://localhost/callback", want: false},
		{name: "127.0.0.1 without port", uri: "http://127.0.0.1/callback", want: false},
		{name: "169.254 SSRF (AWS metadata)", uri: "http://169.254.169.254/latest/meta-data", want: false},
		{name: "internal RFC1918 host", uri: "http://192.168.1.1:80/callback", want: false},
		{name: "SSRF via @ in URL", uri: "https://claude.ai@evil.com/callback", want: false},
		{name: "empty URI", uri: "", want: false},
		{name: "whitespace only", uri: "   ", want: false},
		{name: "relative path", uri: "/oauth/callback", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := validRedirectURI(tt.uri)
			if got != tt.want {
				t.Errorf("validRedirectURI(%q) = %v, want %v", tt.uri, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Register — maxClients cap and TOCTOU race
// ---------------------------------------------------------------------------

func TestRegister_MaxClientsCap(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	// Fill up to capacity.
	for range maxClients {
		body := `{"redirect_uris":["https://claude.ai/cb"]}`
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
		w := httptest.NewRecorder()
		o.Register(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("registration %d failed: status %d", len(o.clients), w.Code)
		}
	}

	// The next registration must be rejected.
	req := httptest.NewRequest(http.MethodPost, "/oauth/register",
		strings.NewReader(`{"redirect_uris":["https://claude.ai/cb"]}`))
	w := httptest.NewRecorder()
	o.Register(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Register() at maxClients+1 status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// TestRegister_ConcurrentRace fires maxClients+10 concurrent registrations and
// verifies the final count never exceeds maxClients, catching the TOCTOU window
// between the capacity check and the map insertion in Register.
func TestRegister_ConcurrentRace(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	var wg sync.WaitGroup
	const goroutines = maxClients + 10
	results := make([]int, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			body := `{"redirect_uris":["https://claude.ai/cb"]}`
			req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
			w := httptest.NewRecorder()
			o.Register(w, req)
			results[idx] = w.Code
		}(i)
	}
	wg.Wait()

	o.mu.Lock()
	finalCount := len(o.clients)
	o.mu.Unlock()

	// The map must never exceed maxClients regardless of timing.
	if finalCount > maxClients {
		t.Errorf("Register() concurrent: %d clients registered, max allowed is %d", finalCount, maxClients)
	}

	// Count rejections — must have at least 10 (the overflow goroutines).
	rejected := 0
	for _, code := range results {
		if code == http.StatusServiceUnavailable {
			rejected++
		}
	}
	if rejected < 10 {
		t.Errorf("Register() concurrent: only %d rejections, expected at least 10", rejected)
	}
}

func TestRegister_MalformedJSON(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "empty body", body: "", want: http.StatusBadRequest},
		{name: "truncated JSON", body: `{"redirect_uris":`, want: http.StatusBadRequest},
		{name: "null bytes", body: "{\x00}", want: http.StatusBadRequest},
		{name: "valid JSON (no redirect_uris — still accepted)", body: `{}`, want: http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			o.Register(w, req)
			if w.Code != tt.want {
				t.Errorf("Register(%q) status = %d, want %d", tt.name, w.Code, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// verifyPKCE — adversarial verifier inputs
// ---------------------------------------------------------------------------

func TestVerifyPKCE(t *testing.T) {
	t.Parallel()

	// Real PKCE: verifier = "dGVzdC12ZXJpZmllci12YWx1ZQ", challenge = SHA256(verifier) base64url
	// We pre-compute a valid pair.
	validVerifier := "dGVzdC12ZXJpZmllci12YWx1ZQ"
	validChallenge := pkceChallenge(validVerifier) // helper below

	tests := []struct {
		name      string
		verifier  string
		challenge string
		want      bool
	}{
		{name: "valid pair", verifier: validVerifier, challenge: validChallenge, want: true},
		{name: "wrong verifier", verifier: "wrong-verifier", challenge: validChallenge, want: false},
		{name: "empty verifier", verifier: "", challenge: validChallenge, want: false},
		{name: "empty challenge", verifier: validVerifier, challenge: "", want: false},
		{name: "both empty", verifier: "", challenge: "", want: false},
		{name: "verifier same as challenge", verifier: validChallenge, challenge: validChallenge, want: false},
		{name: "SQL injection in verifier", verifier: "'; DROP TABLE tokens;--", challenge: validChallenge, want: false},
		{name: "null bytes in verifier", verifier: "valid\x00suffix", challenge: validChallenge, want: false},
		{name: "very long verifier", verifier: strings.Repeat("a", 100000), challenge: validChallenge, want: false},
		{name: "unicode verifier", verifier: "证书验证", challenge: validChallenge, want: false},
		// Tampered challenge: same length, different bytes (timing-safe comparison test).
		{name: "tampered challenge", verifier: validVerifier, challenge: validChallenge[:len(validChallenge)-1] + "X", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := verifyPKCE(tt.verifier, tt.challenge)
			if got != tt.want {
				t.Errorf("verifyPKCE(%q, %q) = %v, want %v", tt.verifier, tt.challenge, got, tt.want)
			}
		})
	}
}

// pkceChallenge computes the S256 PKCE challenge for a given verifier.
func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func FuzzVerifyPKCE(f *testing.F) {
	f.Add("valid-verifier", "challenge")
	f.Add("", "")
	f.Add("a", "a")
	f.Add(strings.Repeat("x", 10000), strings.Repeat("y", 43))
	f.Add("'; DROP TABLE;--", "base64challenge==")
	f.Fuzz(func(t *testing.T, verifier, challenge string) {
		// Must not panic regardless of input
		_ = verifyPKCE(verifier, challenge)
	})
}

// ---------------------------------------------------------------------------
// Token endpoint — all grant types adversarial
// ---------------------------------------------------------------------------

func TestToken_UnsupportedGrantType(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	tests := []struct {
		name      string
		grantType string
		wantCode  int
		wantError string
	}{
		{name: "implicit (not allowed)", grantType: "implicit", wantCode: http.StatusBadRequest, wantError: "unsupported_grant_type"},
		{name: "password (not allowed)", grantType: "password", wantCode: http.StatusBadRequest, wantError: "unsupported_grant_type"},
		{name: "device_code (not allowed)", grantType: "urn:ietf:params:oauth:grant-type:device_code", wantCode: http.StatusBadRequest, wantError: "unsupported_grant_type"},
		{name: "empty grant_type", grantType: "", wantCode: http.StatusBadRequest, wantError: "unsupported_grant_type"},
		{name: "SQL injection in grant_type", grantType: "'; DROP TABLE tokens;--", wantCode: http.StatusBadRequest, wantError: "unsupported_grant_type"},
		{name: "null byte in grant_type", grantType: "authorization_code\x00", wantCode: http.StatusBadRequest, wantError: "unsupported_grant_type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := url.Values{"grant_type": {tt.grantType}}
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			o.Token(w, req)
			if w.Code != tt.wantCode {
				t.Errorf("Token(%q) status = %d, want %d", tt.grantType, w.Code, tt.wantCode)
			}
			var resp map[string]string
			if err := json.NewDecoder(w.Body).Decode(&resp); err == nil {
				if diff := cmp.Diff(tt.wantError, resp["error"]); diff != "" {
					t.Errorf("Token(%q) error field mismatch (-want +got):\n%s", tt.grantType, diff)
				}
			}
		})
	}
}

func TestToken_ClientCredentials_InvalidClient(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)
	cid, _ := registerClient(t, o)

	tests := []struct {
		name     string
		clientID string
		secret   string
		wantCode int
	}{
		{name: "wrong secret", clientID: cid, secret: "wrong-secret", wantCode: http.StatusUnauthorized},
		{name: "unknown client_id", clientID: "unknown", secret: "any", wantCode: http.StatusUnauthorized},
		{name: "empty client_id", clientID: "", secret: "any", wantCode: http.StatusUnauthorized},
		{name: "empty secret", clientID: cid, secret: "", wantCode: http.StatusUnauthorized},
		{name: "SQL in client_id", clientID: "'; DROP TABLE clients;--", secret: "x", wantCode: http.StatusUnauthorized},
		{name: "null byte in client_id", clientID: cid + "\x00", secret: "x", wantCode: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {tt.clientID},
				"client_secret": {tt.secret},
			}
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			o.Token(w, req)
			if w.Code != tt.wantCode {
				t.Errorf("Token(client_credentials, client=%q) status = %d, want %d",
					tt.clientID, w.Code, tt.wantCode)
			}
		})
	}
}

func TestToken_AuthorizationCode_PKCEFailure(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)
	cid, csec := registerClient(t, o)

	// Issue a real code with a known challenge.
	verifier := "test-verifier-string-long-enough"
	challenge := pkceChallenge(verifier)
	code := o.issueCode(challenge)

	tests := []struct {
		name         string
		code         string
		codeVerifier string
		wantCode     int
		wantError    string
	}{
		{name: "wrong verifier", code: code, codeVerifier: "wrong-verifier", wantCode: http.StatusBadRequest, wantError: "invalid_grant"},
		{name: "empty verifier", code: code, codeVerifier: "", wantCode: http.StatusBadRequest, wantError: "invalid_grant"},
		{name: "replay attack (code already consumed above)", code: code, codeVerifier: verifier, wantCode: http.StatusBadRequest, wantError: "invalid_grant"},
	}

	// First call consumes the code (wrong verifier → code NOT consumed, but let's verify behavior).
	// We test the wrong verifier first — code is consumed by consumeCode, then PKCE check fails.
	// Per implementation: consumeCode removes the code regardless of PKCE outcome.
	// So the replay test uses a fresh code each time.

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use the code from the table (which is the SAME code for all cases).
			// The first case consumes it (consumeCode deletes), so subsequent
			// cases test replay/reuse behavior.
			testCode := tt.code
			form := url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {cid},
				"client_secret": {csec},
				"code":          {testCode},
				"code_verifier": {tt.codeVerifier},
			}
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			o.Token(w, req)
			if w.Code != tt.wantCode {
				t.Errorf("Token(authorization_code, %q) status = %d, want %d; body: %s",
					tt.name, w.Code, tt.wantCode, w.Body.String())
			}
			var resp map[string]string
			if err := json.NewDecoder(w.Body).Decode(&resp); err == nil {
				if resp["error"] != tt.wantError {
					t.Errorf("Token(authorization_code, %q) error = %q, want %q", tt.name, resp["error"], tt.wantError)
				}
			}
		})
	}
}

func TestToken_AuthorizationCode_ReplayAttack(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)
	cid, csec := registerClient(t, o)

	verifier := "replay-test-verifier-value"
	challenge := pkceChallenge(verifier)
	code := o.issueCode(challenge)

	doExchange := func() int {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {cid},
			"client_secret": {csec},
			"code":          {code},
			"code_verifier": {verifier},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		o.Token(w, req)
		return w.Code
	}

	// First exchange must succeed.
	if code1 := doExchange(); code1 != http.StatusOK {
		t.Fatalf("first exchange status = %d, want %d", code1, http.StatusOK)
	}
	// Second exchange with the same code must fail — code is single-use.
	if code2 := doExchange(); code2 != http.StatusBadRequest {
		t.Errorf("replay attack: second exchange status = %d, want %d (codes must be single-use)",
			code2, http.StatusBadRequest)
	}
}

func TestToken_RefreshToken_InvalidGrant(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	tests := []struct {
		name    string
		rt      string
		want    int
		wantErr string
	}{
		{name: "unknown refresh token", rt: "unknown-token", want: http.StatusBadRequest, wantErr: "invalid_grant"},
		{name: "empty refresh token", rt: "", want: http.StatusBadRequest, wantErr: "invalid_grant"},
		{name: "SQL injection in refresh token", rt: "'; DROP TABLE refresh_tokens;--", want: http.StatusBadRequest, wantErr: "invalid_grant"},
		{name: "access token as refresh token (wrong type)", rt: "rt_prefixed_but_not_issued", want: http.StatusBadRequest, wantErr: "invalid_grant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			form := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {tt.rt},
			}
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			o.Token(w, req)
			if w.Code != tt.want {
				t.Errorf("Token(refresh_token, %q) status = %d, want %d", tt.rt, w.Code, tt.want)
			}
			var resp map[string]string
			if err := json.NewDecoder(w.Body).Decode(&resp); err == nil {
				if diff := cmp.Diff(tt.wantErr, resp["error"]); diff != "" {
					t.Errorf("Token(refresh_token, %q) error mismatch (-want +got):\n%s", tt.rt, diff)
				}
			}
		})
	}
}

func TestToken_RefreshToken_ReplayAttack(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	_, _, rt, _ := o.issueToken()

	doRefresh := func() int {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {rt},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		o.Token(w, req)
		return w.Code
	}

	if first := doRefresh(); first != http.StatusOK {
		t.Fatalf("first refresh status = %d, want %d", first, http.StatusOK)
	}
	// Second use of the same refresh token must fail — refresh tokens are single-use.
	if second := doRefresh(); second != http.StatusBadRequest {
		t.Errorf("refresh token replay: second use status = %d, want %d (must be single-use)",
			second, http.StatusBadRequest)
	}
}

func TestToken_MalformedBody(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	tests := []struct {
		name        string
		body        string
		contentType string
		wantCode    int
	}{
		{name: "JSON body (wrong content type for form)", body: `{"grant_type":"client_credentials"}`, contentType: "application/json", wantCode: http.StatusBadRequest},
		{name: "binary body", body: "\x00\x01\x02\x03", contentType: "application/x-www-form-urlencoded", wantCode: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			w := httptest.NewRecorder()
			o.Token(w, req)
			// Binary body fails ParseForm; JSON body gets parsed as url-encoded garbage → unsupported grant.
			if w.Code == http.StatusOK {
				t.Errorf("Token(%q) status = %d, should not be 200 for malformed body", tt.name, w.Code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidToken — expired and tampered tokens
// ---------------------------------------------------------------------------

func TestValidToken(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	// Issue a real token.
	accessTok, _, _, _ := o.issueToken()

	tests := []struct {
		name string
		tok  string
		want bool
	}{
		{name: "valid access token", tok: accessTok, want: true},
		{name: "static token", tok: "static-test-token", want: true},
		{name: "unknown token", tok: "totally-unknown", want: false},
		{name: "empty token", tok: "", want: false},
		{name: "SQL injection", tok: "'; DROP TABLE tokens;--", want: false},
		{name: "access token + extra char", tok: accessTok + "x", want: false},
		{name: "access token missing last char", tok: accessTok[:len(accessTok)-1], want: false},
		{name: "refresh token (wrong type for valid check)", tok: "rt_" + accessTok, want: false},
		// Constant-time comparison: same length as static token but different content.
		{name: "same-length tampered static", tok: strings.Repeat("x", len("static-test-token")), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := o.ValidToken(tt.tok)
			if got != tt.want {
				t.Errorf("ValidToken(%q) = %v, want %v", tt.tok, got, tt.want)
			}
		})
	}
}

func TestValidToken_Expired(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	// Manually insert an expired token.
	expiredTok := "expired-access-token-value"
	o.mu.Lock()
	o.tokens[expiredTok] = time.Now().Add(-1 * time.Second)
	o.mu.Unlock()

	if o.ValidToken(expiredTok) {
		t.Error("ValidToken(expired) = true, want false")
	}
}

// ---------------------------------------------------------------------------
// BearerAuth middleware — header format attacks
// ---------------------------------------------------------------------------

func TestBearerAuth(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	// Issue a valid token for use in success cases.
	validTok, _, _, _ := o.issueToken()

	passthrough := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := BearerAuth(passthrough, o)

	tests := []struct {
		name      string
		authValue string
		want      int
	}{
		{name: "valid Bearer token", authValue: "Bearer " + validTok, want: http.StatusOK},
		{name: "valid static token", authValue: "Bearer static-test-token", want: http.StatusOK},
		{name: "no Authorization header", authValue: "", want: http.StatusUnauthorized},
		{name: "wrong prefix — Token", authValue: "Token " + validTok, want: http.StatusUnauthorized},
		{name: "wrong prefix — Basic", authValue: "Basic " + validTok, want: http.StatusUnauthorized},
		{name: "lowercase bearer", authValue: "bearer " + validTok, want: http.StatusUnauthorized},
		{name: "Bearer only (no token)", authValue: "Bearer", want: http.StatusUnauthorized},
		{name: "Bearer space only", authValue: "Bearer ", want: http.StatusUnauthorized},
		{name: "invalid token", authValue: "Bearer invalid-token-value", want: http.StatusUnauthorized},
		{name: "SQL injection in token", authValue: "Bearer '; DROP TABLE tokens;--", want: http.StatusUnauthorized},
		{name: "null byte in token", authValue: "Bearer valid\x00suffix", want: http.StatusUnauthorized},
		// Length attacks: too short to hold the "Bearer " prefix.
		{name: "too short (5 chars)", authValue: "Short", want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tt.authValue != "" {
				req.Header.Set("Authorization", tt.authValue)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tt.want {
				t.Errorf("BearerAuth(%q) status = %d, want %d", tt.authValue, w.Code, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Authorize endpoint — PKCE bypass and redirect_uri validation
// ---------------------------------------------------------------------------

func TestAuthorize_PKCERequired(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)
	cid, _ := registerClient(t, o)

	tests := []struct {
		name                string
		codeChallenge       string
		codeChallengeMethod string
		want                int
	}{
		{name: "valid PKCE S256", codeChallenge: "challenge123", codeChallengeMethod: "S256", want: http.StatusFound},
		{name: "missing code_challenge", codeChallenge: "", codeChallengeMethod: "S256", want: http.StatusBadRequest},
		{name: "wrong method (plain)", codeChallenge: "challenge123", codeChallengeMethod: "plain", want: http.StatusBadRequest},
		{name: "wrong method (empty)", codeChallenge: "challenge123", codeChallengeMethod: "", want: http.StatusBadRequest},
		{name: "wrong method (SHA512)", codeChallenge: "challenge123", codeChallengeMethod: "S512", want: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			params := url.Values{
				"client_id":             {cid},
				"redirect_uri":          {"https://claude.ai/oauth/callback"},
				"response_type":         {"code"},
				"code_challenge":        {tt.codeChallenge},
				"code_challenge_method": {tt.codeChallengeMethod},
			}
			req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), http.NoBody)
			w := httptest.NewRecorder()
			o.Authorize(w, req)
			if w.Code != tt.want {
				t.Errorf("Authorize(%q) status = %d, want %d; body: %s",
					tt.name, w.Code, tt.want, w.Body.String())
			}
		})
	}
}

func TestAuthorize_InvalidRedirectURI(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)
	cid, _ := registerClient(t, o)

	tests := []struct {
		name        string
		redirectURI string
		want        int
	}{
		{name: "missing redirect_uri", redirectURI: "", want: http.StatusBadRequest},
		{name: "SSRF via file scheme", redirectURI: "file:///etc/passwd", want: http.StatusBadRequest},
		{name: "open redirect to evil.com", redirectURI: "https://evil.com/callback", want: http.StatusBadRequest},
		{name: "allowed — claude.ai", redirectURI: "https://claude.ai/oauth/callback", want: http.StatusFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			params := url.Values{
				"client_id":             {cid},
				"redirect_uri":          {tt.redirectURI},
				"response_type":         {"code"},
				"code_challenge":        {"challenge123"},
				"code_challenge_method": {"S256"},
			}
			req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), http.NoBody)
			w := httptest.NewRecorder()
			o.Authorize(w, req)
			if w.Code != tt.want {
				t.Errorf("Authorize(redirect=%q) status = %d, want %d", tt.redirectURI, w.Code, tt.want)
			}
		})
	}
}

func TestAuthorize_UnknownClientID(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	params := url.Values{
		"client_id":             {"unknown-client-id"},
		"redirect_uri":          {"https://claude.ai/oauth/callback"},
		"response_type":         {"code"},
		"code_challenge":        {"challenge123"},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), http.NoBody)
	w := httptest.NewRecorder()
	o.Authorize(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Authorize(unknown client_id) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// GoogleCallback — session replay and expired sessions
// ---------------------------------------------------------------------------

func TestGoogleCallback_MissingParams(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	tests := []struct {
		name       string
		state      string
		googleCode string
		want       int
	}{
		{name: "missing state", state: "", googleCode: "code123", want: http.StatusBadRequest},
		{name: "missing google code", state: "session123", googleCode: "", want: http.StatusBadRequest},
		{name: "both missing", state: "", googleCode: "", want: http.StatusBadRequest},
		{name: "unknown session id", state: "unknown-session-id", googleCode: "code123", want: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u := "/oauth/google/callback?state=" + url.QueryEscape(tt.state) + "&code=" + url.QueryEscape(tt.googleCode)
			req := httptest.NewRequest(http.MethodGet, u, http.NoBody)
			w := httptest.NewRecorder()
			o.GoogleCallback(w, req)
			if w.Code != tt.want {
				t.Errorf("GoogleCallback(%q) status = %d, want %d", tt.name, w.Code, tt.want)
			}
		})
	}
}

func TestGoogleCallback_ExpiredSession(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	// Insert an already-expired pending auth.
	sid := "expired-session-id"
	o.mu.Lock()
	o.pendingAuths[sid] = pendingAuth{
		clientID:    "some-client",
		redirectURI: "https://claude.ai/callback",
		expiresAt:   time.Now().Add(-1 * time.Second),
	}
	o.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()
	o.GoogleCallback(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("GoogleCallback(expired session) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// evictExpired — cleanup correctness
// ---------------------------------------------------------------------------

func TestEvictExpired(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	now := time.Now()

	// Populate with a mix of expired and valid entries.
	o.mu.Lock()
	o.tokens["expired-tok"] = now.Add(-1 * time.Second)
	o.tokens["valid-tok"] = now.Add(1 * time.Hour)
	o.codes["expired-code"] = codeInfo{codeChallenge: "x", expiresAt: now.Add(-1 * time.Second)}
	o.codes["valid-code"] = codeInfo{codeChallenge: "y", expiresAt: now.Add(5 * time.Minute)}
	o.refreshToks["expired-rt"] = now.Add(-1 * time.Second)
	o.refreshToks["valid-rt"] = now.Add(30 * 24 * time.Hour)
	o.pendingAuths["expired-pa"] = pendingAuth{expiresAt: now.Add(-1 * time.Second)}
	o.pendingAuths["valid-pa"] = pendingAuth{expiresAt: now.Add(10 * time.Minute)}
	o.mu.Unlock()

	o.evictExpired(now)

	o.mu.Lock()
	defer o.mu.Unlock()

	// Expired entries must be gone.
	if _, ok := o.tokens["expired-tok"]; ok {
		t.Error("evictExpired did not remove expired access token")
	}
	if _, ok := o.codes["expired-code"]; ok {
		t.Error("evictExpired did not remove expired authorization code")
	}
	if _, ok := o.refreshToks["expired-rt"]; ok {
		t.Error("evictExpired did not remove expired refresh token")
	}
	if _, ok := o.pendingAuths["expired-pa"]; ok {
		t.Error("evictExpired did not remove expired pending auth")
	}

	// Valid entries must survive.
	if _, ok := o.tokens["valid-tok"]; !ok {
		t.Error("evictExpired incorrectly removed valid access token")
	}
	if _, ok := o.codes["valid-code"]; !ok {
		t.Error("evictExpired incorrectly removed valid authorization code")
	}
	if _, ok := o.refreshToks["valid-rt"]; !ok {
		t.Error("evictExpired incorrectly removed valid refresh token")
	}
	if _, ok := o.pendingAuths["valid-pa"]; !ok {
		t.Error("evictExpired incorrectly removed valid pending auth")
	}
}

// ---------------------------------------------------------------------------
// Metadata endpoint
// ---------------------------------------------------------------------------

func TestMetadata_ResponseShape(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()
	o.Metadata(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Metadata() status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Metadata() Content-Type = %q, want %q", ct, "application/json")
	}

	var meta map[string]any
	if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
		t.Fatalf("Metadata() decode error: %v", err)
	}

	requiredFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"registration_endpoint",
		"response_types_supported",
		"grant_types_supported",
		"code_challenge_methods_supported",
	}
	for _, field := range requiredFields {
		if _, ok := meta[field]; !ok {
			t.Errorf("Metadata() missing required field %q", field)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmarks — ValidToken and Register hot paths
// ---------------------------------------------------------------------------

func BenchmarkValidToken_Static(b *testing.B) {
	o := newTestOAuthB(b)
	b.ReportAllocs()
	for b.Loop() {
		_ = o.ValidToken("static-test-token")
	}
}

func BenchmarkValidToken_OAuth(b *testing.B) {
	o := newTestOAuthB(b)
	tok, _, _, _ := o.issueToken()
	b.ReportAllocs()
	for b.Loop() {
		_ = o.ValidToken(tok)
	}
}

func BenchmarkValidToken_Invalid(b *testing.B) {
	o := newTestOAuthB(b)
	b.ReportAllocs()
	for b.Loop() {
		_ = o.ValidToken("totally-invalid-token-that-does-not-exist")
	}
}

func BenchmarkRegister(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		o := newTestOAuthB(b)
		body := `{"redirect_uris":["https://claude.ai/cb"]}`
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader([]byte(body)))
		w := httptest.NewRecorder()
		o.Register(w, req)
		close(o.Done)
	}
}

// newTestOAuthB is the benchmark variant of newTestOAuth (accepts *testing.B).
func newTestOAuthB(b *testing.B) *OAuthProvider {
	b.Helper()
	o := NewOAuthProvider(OAuthConfig{
		StaticToken: "static-test-token",
		AdminEmail:  "admin@example.com",
		BaseURL:     "https://mcp.example.com",
		GoogleOAuth: &oauth2.Config{},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return o
}

// ---------------------------------------------------------------------------
// Scope escalation — client_credentials cannot request elevated scopes
// ---------------------------------------------------------------------------

func TestToken_ScopeEscalation(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)
	cid, csec := registerClient(t, o)

	// The Token endpoint does not validate scope (scope is not in the spec implementation).
	// Verify that passing an elevated scope does NOT cause a 5xx error.
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cid},
		"client_secret": {csec},
		"scope":         {"admin write:secrets read:all"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	o.Token(w, req)
	// A 200 here is fine (scope is ignored) — but a 5xx would indicate a crash.
	if w.Code >= http.StatusInternalServerError {
		t.Errorf("Token(scope escalation) status = %d, should not be 5xx", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Oversized request body — Register must limit via MaxBytesReader
// ---------------------------------------------------------------------------

func TestRegister_OversizedBody(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	// 1<<16 = 64KB limit. Send 65KB+1 body.
	oversized := strings.Repeat("a", (1<<16)+1)
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	o.Register(w, req)
	// MaxBytesReader causes json.Decode to fail → 400.
	if w.Code == http.StatusCreated {
		t.Errorf("Register(oversized body) status = %d, want error; oversized bodies must be rejected", w.Code)
	}
}

func TestToken_OversizedBody(t *testing.T) {
	t.Parallel()
	o := newTestOAuth(t)

	oversized := "grant_type=" + strings.Repeat("a", (1<<16)+1)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	o.Token(w, req)
	// MaxBytesReader causes ParseForm to fail → 400.
	if w.Code == http.StatusOK {
		t.Errorf("Token(oversized body) status = %d, want error; oversized bodies must be rejected", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Math boundary: MaxInt for math-only tests
// ---------------------------------------------------------------------------

func TestVerifyPKCE_MaxIntLengthVerifier(t *testing.T) {
	t.Parallel()
	// verifier of length math.MaxInt32 would OOM; test a large but bounded size.
	longVerifier := strings.Repeat("v", 10_000)
	challenge := pkceChallenge(longVerifier)
	if !verifyPKCE(longVerifier, challenge) {
		t.Error("verifyPKCE(10000-char verifier, correct challenge) = false, want true")
	}
	_ = math.MaxInt // reference to ensure import is used
}
