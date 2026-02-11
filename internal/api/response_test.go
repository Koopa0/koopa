package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// decodeData extracts the data field from an envelope response into target.
func decodeData(t *testing.T, w *httptest.ResponseRecorder, target any) {
	t.Helper()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decoding envelope: %v", err)
	}
	if err := json.Unmarshal(env.Data, target); err != nil {
		t.Fatalf("decoding envelope data: %v", err)
	}
}

// decodeErrorEnvelope extracts the error field from an envelope response.
func decodeErrorEnvelope(t *testing.T, w *httptest.ResponseRecorder) Error {
	t.Helper()
	var env struct {
		Error *Error `json:"error"`
	}
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decoding envelope: %v", err)
	}
	if env.Error == nil {
		t.Fatal("expected error in envelope, got nil")
	}
	return *env.Error
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()

	data := map[string]string{"key": "value"}
	WriteJSON(w, http.StatusOK, data, nil)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("WriteJSON() Content-Type = %q, want %q", ct, "application/json")
	}

	if w.Code != http.StatusOK {
		t.Errorf("WriteJSON() status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	decodeData(t, w, &body)

	if body["key"] != "value" {
		t.Errorf("WriteJSON() data[key] = %q, want %q", body["key"], "value")
	}
}

func TestWriteJSON_Envelope(t *testing.T) {
	w := httptest.NewRecorder()

	items := []string{"a", "b"}
	WriteJSON(w, http.StatusOK, items, nil)

	var body []string
	decodeData(t, w, &body)

	if len(body) != 2 || body[0] != "a" || body[1] != "b" {
		t.Errorf("WriteJSON() data = %v, want [a b]", body)
	}
}

func TestWriteJSON_NilData(t *testing.T) {
	w := httptest.NewRecorder()

	WriteJSON(w, http.StatusNoContent, nil, nil)

	if w.Code != http.StatusNoContent {
		t.Errorf("WriteJSON(nil) status = %d, want %d", w.Code, http.StatusNoContent)
	}

	if w.Body.Len() != 0 {
		t.Errorf("WriteJSON(nil) body length = %d, want 0", w.Body.Len())
	}
}

func TestWriteJSON_CustomStatus(t *testing.T) {
	w := httptest.NewRecorder()

	WriteJSON(w, http.StatusCreated, map[string]string{"id": "123"}, nil)

	if w.Code != http.StatusCreated {
		t.Errorf("WriteJSON() status = %d, want %d", w.Code, http.StatusCreated)
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()

	WriteError(w, http.StatusBadRequest, "invalid_input", "name is required", nil)

	if w.Code != http.StatusBadRequest {
		t.Errorf("WriteError() status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	body := decodeErrorEnvelope(t, w)

	if body.Code != "invalid_input" {
		t.Errorf("WriteError() code = %q, want %q", body.Code, "invalid_input")
	}
	if body.Message != "name is required" {
		t.Errorf("WriteError() message = %q, want %q", body.Message, "name is required")
	}
}
