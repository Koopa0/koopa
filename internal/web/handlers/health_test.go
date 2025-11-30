package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealth_Health(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	w := httptest.NewRecorder()

	health(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("health() status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()
	if body != "ok" {
		t.Errorf("health() body = %q, want %q", body, "ok")
	}
}

func TestHealth_RegisterRoutes(t *testing.T) {
	h := NewHealth()

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Test health route
	reqHealth := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	wHealth := httptest.NewRecorder()
	mux.ServeHTTP(wHealth, reqHealth)

	if wHealth.Code != http.StatusOK {
		t.Errorf("registered /health status = %d, want %d", wHealth.Code, http.StatusOK)
	}

	// Test ready route (should be same as health)
	reqReady := httptest.NewRequest(http.MethodGet, "/ready", http.NoBody)
	wReady := httptest.NewRecorder()
	mux.ServeHTTP(wReady, reqReady)

	if wReady.Code != http.StatusOK {
		t.Errorf("registered /ready status = %d, want %d", wReady.Code, http.StatusOK)
	}
}
