package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
)

const testSecret = "test-secret-for-auth-unit-tests"

// signToken creates a signed JWT for testing.
func signToken(t *testing.T, email, secret string, expiresAt time.Time, method jwt.SigningMethod) string { //nolint:unparam // test helper designed for varied emails
	t.Helper()
	claims := Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("signing test token: %v", err)
	}
	return signed
}

// callMiddleware sends a request through the auth middleware and returns the response.
func callMiddleware(t *testing.T, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	var captured *Claims
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := ClaimsFromContext(r.Context())
		captured = c
		w.WriteHeader(http.StatusOK)
	})

	mid := Middleware(testSecret)
	handler := mid(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/test", http.NoBody)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// If the middleware passed, verify claims were set
	if w.Code == http.StatusOK && captured == nil {
		t.Error("middleware passed but claims not found in context")
	}

	return w
}

func TestMiddleware(t *testing.T) {
	validToken := signToken(t, "admin@koopa0.dev", testSecret, time.Now().Add(time.Hour), jwt.SigningMethodHS256)
	expiredToken := signToken(t, "admin@koopa0.dev", testSecret, time.Now().Add(-time.Hour), jwt.SigningMethodHS256)
	wrongSecretToken := signToken(t, "admin@koopa0.dev", "wrong-secret", time.Now().Add(time.Hour), jwt.SigningMethodHS256)

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "missing authorization header",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid format no bearer prefix",
			authHeader: "Basic dXNlcjpwYXNz",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "bearer prefix only no token",
			authHeader: "Bearer ",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "expired token",
			authHeader: "Bearer " + expiredToken,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong signing secret",
			authHeader: "Bearer " + wrongSecretToken,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "garbage token",
			authHeader: "Bearer not.a.valid.jwt",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "valid token",
			authHeader: "Bearer " + validToken,
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := callMiddleware(t, tt.authHeader)
			if w.Code != tt.wantStatus {
				t.Errorf("Middleware(%q) status = %d, want %d", tt.name, w.Code, tt.wantStatus)
			}
		})
	}
}

func TestMiddleware_AlgorithmConfusion(t *testing.T) {
	// An attacker might try to use a different signing algorithm (e.g., RS256)
	// or the "none" algorithm to bypass validation. The middleware must reject
	// any token not signed with HMAC.

	// Create a token with "none" algorithm by manually constructing it.
	// jwt-go v5 doesn't support signing with "none", so we test that the
	// middleware's method check rejects non-HMAC algorithms.
	t.Run("none algorithm rejected", func(t *testing.T) {
		// Manually craft a token header with alg:none
		// This won't be a valid JWT but should be rejected before signature check
		w := callMiddleware(t, "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6ImFkbWluQGtvb3BhMC5kZXYifQ.")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("none algorithm: status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})
}

func TestMiddleware_ClaimsPassedToHandler(t *testing.T) {
	validToken := signToken(t, "admin@koopa0.dev", testSecret, time.Now().Add(time.Hour), jwt.SigningMethodHS256)

	var gotClaims *Claims
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := ClaimsFromContext(r.Context())
		if !ok {
			t.Error("ClaimsFromContext returned false")
			return
		}
		gotClaims = c
		w.WriteHeader(http.StatusOK)
	})

	mid := Middleware(testSecret)
	handler := mid(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+validToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if gotClaims == nil {
		t.Fatal("claims not passed to handler")
	}
	if gotClaims.Email != "admin@koopa0.dev" {
		t.Errorf("claims.Email = %q, want %q", gotClaims.Email, "admin@koopa0.dev")
	}
}

func TestMiddleware_ErrorResponseFormat(t *testing.T) {
	// Verify error responses match the api.ErrorBody JSON format
	w := callMiddleware(t, "")

	var errResp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("decoding error response: %v", err)
	}
	if errResp.Error.Code != "UNAUTHORIZED" {
		t.Errorf("error.code = %q, want %q", errResp.Error.Code, "UNAUTHORIZED")
	}
	if errResp.Error.Message == "" {
		t.Error("error.message should not be empty")
	}
}

func TestClaimsFromContext(t *testing.T) {
	tests := []struct {
		name      string
		ctx       context.Context
		wantOK    bool
		wantEmail string
	}{
		{
			name:   "no claims in context",
			ctx:    context.Background(),
			wantOK: false,
		},
		{
			name:      "claims present",
			ctx:       context.WithValue(context.Background(), claimsKey, &Claims{Email: "admin@koopa0.dev"}),
			wantOK:    true,
			wantEmail: "admin@koopa0.dev",
		},
		{
			name:   "wrong type in context",
			ctx:    context.WithValue(context.Background(), claimsKey, "not-claims"),
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, ok := ClaimsFromContext(tt.ctx)
			if ok != tt.wantOK {
				t.Errorf("ClaimsFromContext() ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && claims.Email != tt.wantEmail {
				t.Errorf("ClaimsFromContext().Email = %q, want %q", claims.Email, tt.wantEmail)
			}
		})
	}
}

func TestGenerateAndValidateState(t *testing.T) {
	h := &Handler{secret: []byte(testSecret)}

	t.Run("valid state", func(t *testing.T) {
		state, err := h.generateState()
		if err != nil {
			t.Fatalf("generateState() unexpected error: %v", err)
		}
		if !h.validateState(state) {
			t.Errorf("validateState(%q) = false, want true", state)
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		state, err := h.generateState()
		if err != nil {
			t.Fatalf("generateState() unexpected error: %v", err)
		}
		// Flip a character in the signature portion
		tampered := state[:len(state)-1] + "X"
		if h.validateState(tampered) {
			t.Errorf("validateState(tampered) = true, want false")
		}
	})

	t.Run("malformed no dot separator", func(t *testing.T) {
		if h.validateState("nodothere") {
			t.Error("validateState(no dot) = true, want false")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		if h.validateState("") {
			t.Error("validateState(empty) = true, want false")
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		state, err := h.generateState()
		if err != nil {
			t.Fatalf("generateState() unexpected error: %v", err)
		}
		other := &Handler{secret: []byte("different-secret")}
		if other.validateState(state) {
			t.Error("validateState with wrong secret = true, want false")
		}
	})

	t.Run("expired state", func(t *testing.T) {
		// Manually create a valid state with a timestamp 10 minutes in the past.
		// Uses the same HMAC construction as generateState but with a past timestamp.
		pastUnix := time.Now().Add(-10 * time.Minute).Unix()
		expiredState := generateStateAt(h, pastUnix)
		if h.validateState(expiredState) {
			t.Error("validateState(expired) = true, want false")
		}
	})
}

// generateStateAt creates a correctly signed state string with a specific unix timestamp.
// Uses a fixed nonce for deterministic test output.
func generateStateAt(h *Handler, unix int64) string {
	ts := strconv.FormatInt(unix, 10)
	nonce := base64.URLEncoding.EncodeToString([]byte("testnonce"))
	payload := ts + "." + nonce
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(payload))
	sig := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig
}

func TestHashToken(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		h1 := hashToken("test-token-123")
		h2 := hashToken("test-token-123")
		if h1 != h2 {
			t.Errorf("hashToken not deterministic: %q != %q", h1, h2)
		}
	})

	t.Run("different inputs produce different hashes", func(t *testing.T) {
		h1 := hashToken("token-a")
		h2 := hashToken("token-b")
		if h1 == h2 {
			t.Error("different inputs produced same hash")
		}
	})

	t.Run("non-empty output", func(t *testing.T) {
		h := hashToken("anything")
		if h == "" {
			t.Error("hashToken returned empty string")
		}
	})
}

func TestSignAccessToken(t *testing.T) {
	h := &Handler{secret: []byte(testSecret)}

	tokenStr, err := h.signAccessToken("admin@koopa0.dev")
	if err != nil {
		t.Fatalf("signAccessToken() error: %v", err)
	}

	// Parse it back and verify claims
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
		return []byte(testSecret), nil
	})
	if err != nil {
		t.Fatalf("parsing signed token: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("signed token is not valid")
	}
	if claims.Email != "admin@koopa0.dev" {
		t.Errorf("claims.Email = %q, want %q", claims.Email, "admin@koopa0.dev")
	}
	if claims.Subject != "admin@koopa0.dev" {
		t.Errorf("claims.Subject = %q, want %q", claims.Subject, "admin@koopa0.dev")
	}
}

func TestSignAccessToken_RoundTrip(t *testing.T) {
	// Verify that signAccessToken produces tokens the Middleware accepts
	h := &Handler{secret: []byte(testSecret)}

	tokenStr, err := h.signAccessToken("admin@koopa0.dev")
	if err != nil {
		t.Fatalf("signAccessToken() error: %v", err)
	}

	w := callMiddleware(t, "Bearer "+tokenStr)
	if w.Code != http.StatusOK {
		t.Errorf("Middleware rejected signAccessToken output: status = %d, want %d", w.Code, http.StatusOK)
	}
}

func FuzzValidateState(f *testing.F) {
	h := &Handler{secret: []byte(testSecret)}

	// Seed with realistic values
	seed, _ := h.generateState()
	f.Add(seed)
	f.Add("")
	f.Add("1234567890.AAAA")
	f.Add("not-a-state")
	f.Add(".")
	f.Add("..")
	f.Add("abc.def.ghi")

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic on any input
		_ = h.validateState(input)
	})
}

func FuzzMiddleware(f *testing.F) {
	f.Add("")
	f.Add("Bearer ")
	f.Add("Bearer abc.def.ghi")
	f.Add("Basic dXNlcjpwYXNz")
	f.Add("Bearer eyJhbGciOiJub25lIn0.e30.")

	mid := Middleware(testSecret)
	handler := mid(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	f.Fuzz(func(t *testing.T, authHeader string) {
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		w := httptest.NewRecorder()
		// Must not panic on any input
		handler.ServeHTTP(w, req)
	})
}

// Verify cmp is used (compile-time check for import)
var _ = cmp.Diff
