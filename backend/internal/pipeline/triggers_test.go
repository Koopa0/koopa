package pipeline

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestTriggers returns a Triggers with no optional deps for HTTP tests.
func newTestTriggers(t *testing.T) *Triggers {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	return NewTriggers(nil, logger)
}

// ---------------------------------------------------------------------------
// Generate — always returns 501
// ---------------------------------------------------------------------------

func TestTriggersGenerate(t *testing.T) {
	t.Parallel()
	tr := newTestTriggers(t)

	req := httptest.NewRequest("POST", "/api/pipeline/generate", http.NoBody)
	w := httptest.NewRecorder()

	tr.Generate(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("Generate() status = %d, want %d", w.Code, http.StatusNotImplemented)
	}
}

// ---------------------------------------------------------------------------
// Collect — not configured returns 501
// ---------------------------------------------------------------------------

func TestTriggersCollect_NotConfigured(t *testing.T) {
	t.Parallel()
	tr := newTestTriggers(t) // no collector

	req := httptest.NewRequest("POST", "/api/pipeline/collect", http.NoBody)
	w := httptest.NewRecorder()

	tr.Collect(w, req, syncBG)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("Collect() not configured: status = %d, want %d", w.Code, http.StatusNotImplemented)
	}
}

// ---------------------------------------------------------------------------
// NotionSync — not configured returns 503
// ---------------------------------------------------------------------------

func TestTriggersNotionSync_NotConfigured(t *testing.T) {
	t.Parallel()
	tr := newTestTriggers(t) // no notionSync

	req := httptest.NewRequest("POST", "/api/pipeline/notion-sync", http.NoBody)
	w := httptest.NewRecorder()

	tr.NotionSync(w, req, syncBG)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("NotionSync() not configured: status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// ---------------------------------------------------------------------------
// Reconcile — not configured returns 503
// ---------------------------------------------------------------------------

func TestTriggersReconcile_NotConfigured(t *testing.T) {
	t.Parallel()
	tr := newTestTriggers(t) // no reconciler

	req := httptest.NewRequest("POST", "/api/pipeline/reconcile", http.NoBody)
	w := httptest.NewRecorder()

	tr.Reconcile(w, req, syncBG)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Reconcile() not configured: status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// ---------------------------------------------------------------------------
// Digest — adversarial inputs
// ---------------------------------------------------------------------------

func TestTriggersDigest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "missing both dates",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing end_date",
			body:       `{"start_date":"2025-01-01"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing start_date",
			body:       `{"end_date":"2025-01-07"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty strings for dates",
			body:       `{"start_date":"","end_date":""}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "malformed JSON",
			body:       `{not valid}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty body",
			body:       ``,
			wantStatus: http.StatusBadRequest,
		},
		// SQL injection in date fields: defense is parameterized queries in the
		// jobs runner, not input validation here. Dates are opaque strings passed
		// to the AI flow. With a nil jobs runner this panics, so this case is
		// tested via integration tests with a real runner instead.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tr := newTestTriggers(t)

			req := httptest.NewRequest("POST", "/api/pipeline/digest", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			tr.Digest(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Digest(%q) status = %d, want %d\nbody: %s", tt.body, w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bookmark — adversarial inputs
// ---------------------------------------------------------------------------

func TestTriggersBookmark(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "missing collected_data_id",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid UUID",
			body:       `{"collected_data_id":"not-a-uuid"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty string UUID",
			body:       `{"collected_data_id":""}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "SQL injection as UUID",
			body:       `{"collected_data_id":"'; DROP TABLE --"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "malformed JSON",
			body:       `{invalid}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty body",
			body:       ``,
			wantStatus: http.StatusBadRequest,
		},
		// Valid UUID with nil jobs runner panics; tested via integration tests.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tr := newTestTriggers(t)

			req := httptest.NewRequest("POST", "/api/pipeline/bookmark", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			tr.Bookmark(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Bookmark(%q) status = %d, want %d\nbody: %s", tt.body, w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Digest — oversized body
// ---------------------------------------------------------------------------

func TestTriggersDigest_OversizedBody(t *testing.T) {
	t.Parallel()
	tr := newTestTriggers(t)

	// body larger than 4096 bytes
	large := `{"start_date":"` + strings.Repeat("x", 5000) + `","end_date":"2025-01-07"}`

	req := httptest.NewRequest("POST", "/api/pipeline/digest", strings.NewReader(large))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	tr.Digest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Digest(oversized) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// Bookmark — oversized body
// ---------------------------------------------------------------------------

func TestTriggersBookmark_OversizedBody(t *testing.T) {
	t.Parallel()
	tr := newTestTriggers(t)

	large := `{"collected_data_id":"` + strings.Repeat("x", 5000) + `"}`

	req := httptest.NewRequest("POST", "/api/pipeline/bookmark", strings.NewReader(large))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	tr.Bookmark(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Bookmark(oversized) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
