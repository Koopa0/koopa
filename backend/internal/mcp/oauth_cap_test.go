package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// newTestOAuthProvider creates an OAuthProvider with no Google OAuth config,
// suitable for testing the registration endpoint in isolation.
func newTestOAuthProvider(t *testing.T) *OAuthProvider {
	t.Helper()
	o := NewOAuthProvider(OAuthConfig{
		StaticToken: "test-static-token",
		AdminEmail:  "admin@example.com",
		BaseURL:     "https://mcp.example.com",
		GoogleOAuth: nil, // not needed for registration tests
	}, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { close(o.Done) })
	return o
}

// registerClient sends a POST /oauth/register request and returns the recorder.
func registerClientNamed(t *testing.T, o *OAuthProvider, name string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://claude.ai/callback"},
		"client_name":   name,
	})
	if err != nil {
		t.Fatalf("marshaling register request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	o.Register(w, req)
	return w
}

// TestRegression_OAuthClientRegistrationCapped verifies that the OAuth
// registration endpoint rejects requests after maxClients registrations.
//
// Regression: before the fix, Register() had no upper bound on client
// registration. An attacker could register thousands of clients, exhausting
// the server's memory. The fix adds: if len(o.clients) >= maxClients { reject }.
//
// This test would fail if the cap check were removed from Register().
func TestRegression_OAuthClientRegistrationCapped(t *testing.T) {
	t.Parallel()

	o := newTestOAuthProvider(t)

	// Register exactly maxClients clients — all must succeed.
	for i := range maxClients {
		w := registerClientNamed(t, o, fmt.Sprintf("client-%d", i))
		if w.Code != http.StatusCreated {
			t.Fatalf("registration %d of %d: status = %d, want %d",
				i+1, maxClients, w.Code, http.StatusCreated)
		}
	}

	// Verify the map is now at capacity.
	o.mu.Lock()
	count := len(o.clients)
	o.mu.Unlock()
	if count != maxClients {
		t.Fatalf("after %d registrations: client count = %d, want %d",
			maxClients, count, maxClients)
	}

	// The (maxClients+1)th registration must be rejected.
	w := registerClientNamed(t, o, "one-too-many")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("registration %d (over cap): status = %d, want %d (503 ServiceUnavailable)",
			maxClients+1, w.Code, http.StatusServiceUnavailable)
	}
}

// TestRegression_OAuthClientRegistrationCapConstant ensures the cap is exactly
// 100. Changing this constant changes the attack surface and must be explicit.
func TestRegression_OAuthClientRegistrationCapConstant(t *testing.T) {
	t.Parallel()

	const want = 100
	if maxClients != want {
		t.Errorf("maxClients = %d, want %d — changing this constant requires security review",
			maxClients, want)
	}
}

// TestRegression_OAuthClientRegistrationCapNotExceeded verifies that the
// client map never exceeds maxClients even under concurrent registration.
// If the cap check were removed, concurrent registrations could race past
// the limit.
func TestRegression_OAuthClientRegistrationCapNotExceeded(t *testing.T) {
	t.Parallel()

	o := newTestOAuthProvider(t)

	// Attempt maxClients+20 concurrent registrations.
	results := make(chan int, maxClients+20)
	var wg sync.WaitGroup
	for i := range maxClients + 20 {
		name := fmt.Sprintf("client-%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := registerClientNamed(t, o, name)
			results <- w.Code
		}()
	}
	wg.Wait()
	close(results)

	created := 0
	rejected := 0
	for code := range results {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusServiceUnavailable:
			rejected++
		default:
			t.Errorf("unexpected status code %d from Register", code)
		}
	}

	o.mu.Lock()
	count := len(o.clients)
	o.mu.Unlock()

	if count > maxClients {
		t.Errorf("client map size = %d, want <= %d — cap not enforced under concurrency",
			count, maxClients)
	}
	if created > maxClients {
		t.Errorf("created = %d, want <= %d — cap not enforced under concurrency",
			created, maxClients)
	}
	if rejected == 0 {
		t.Error("no registrations rejected — cap was never reached, test may not be exercising the limit")
	}
}
