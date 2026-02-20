package api

import (
	"encoding/json"
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

func TestReadiness_NilPool(t *testing.T) {
	handler := readiness(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ready", nil)

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("readiness(nil) status = %d, want %d", w.Code, http.StatusOK)
	}

	// Parse the envelope to verify structure
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if env.Data["status"] != "ok" {
		t.Errorf("readiness(nil) data.status = %v, want %q", env.Data["status"], "ok")
	}

	// nil pool should NOT have db stats
	if _, ok := env.Data["db"]; ok {
		t.Error("readiness(nil) should not include db stats")
	}
}
