package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health", nil)

	health(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("health() status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	decodeData(t, w, &body)

	if body["status"] != "ok" {
		t.Errorf("health() status = %q, want %q", body["status"], "ok")
	}
}
