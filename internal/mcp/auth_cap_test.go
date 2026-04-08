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

func newTestProvider(t *testing.T) *Provider {
	t.Helper()
	o := NewAuth(AuthConfig{
		StaticToken: "test-static-token",
		AdminEmail:  "admin@example.com",
		BaseURL:     "https://mcp.example.com",
		GoogleOAuth: nil,
	}, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { close(o.Done) })
	return o
}

func registerClientNamed(t *testing.T, o *Provider, name string) *httptest.ResponseRecorder {
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

func TestRegression_OAuthClientRegistrationCapped(t *testing.T) {
	t.Parallel()
	o := newTestProvider(t)
	for i := range MaxClients {
		w := registerClientNamed(t, o, fmt.Sprintf("client-%d", i))
		if w.Code != http.StatusCreated {
			t.Fatalf("registration %d of %d: status = %d, want %d", i+1, MaxClients, w.Code, http.StatusCreated)
		}
	}
	o.mu.Lock()
	count := len(o.clients)
	o.mu.Unlock()
	if count != MaxClients {
		t.Fatalf("after %d registrations: client count = %d, want %d", MaxClients, count, MaxClients)
	}
	w := registerClientNamed(t, o, "one-too-many")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("registration %d (over cap): status = %d, want %d", MaxClients+1, w.Code, http.StatusServiceUnavailable)
	}
}

func TestRegression_OAuthClientRegistrationCapConstant(t *testing.T) {
	t.Parallel()
	const want = 100
	if MaxClients != want {
		t.Errorf("MaxClients = %d, want %d", MaxClients, want)
	}
}

func TestRegression_OAuthClientRegistrationCapNotExceeded(t *testing.T) {
	t.Parallel()
	o := newTestProvider(t)
	results := make(chan int, MaxClients+20)
	var wg sync.WaitGroup
	for i := range MaxClients + 20 {
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
	created, rejected := 0, 0
	for code := range results {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusServiceUnavailable:
			rejected++
		default:
			t.Errorf("unexpected status code %d", code)
		}
	}
	o.mu.Lock()
	count := len(o.clients)
	o.mu.Unlock()
	if count > MaxClients {
		t.Errorf("client map size = %d, want <= %d", count, MaxClients)
	}
	if created > MaxClients {
		t.Errorf("created = %d, want <= %d", created, MaxClients)
	}
	if rejected == 0 {
		t.Error("no registrations rejected")
	}
}
