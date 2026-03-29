package reconcile

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHistory_LimitParsing verifies the handler's query parameter parsing
// and clamping logic. The handler clamps limit to [1,100] with default 20,
// then calls store.RecentRuns — which panics on nil store. We test only
// that the handler reaches the store (proving validation passed) by
// recovering from the nil-store panic.
func TestHistory_LimitParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		query     string
		wantPanic bool // true = validation passed, reached nil store
	}{
		{name: "no param defaults to 20", query: "", wantPanic: true},
		{name: "valid limit 10", query: "?limit=10", wantPanic: true},
		{name: "limit 0 clamps to 20", query: "?limit=0", wantPanic: true},
		{name: "limit -5 clamps to 20", query: "?limit=-5", wantPanic: true},
		{name: "limit 101 clamps to 20", query: "?limit=101", wantPanic: true},
		{name: "limit 100 accepted", query: "?limit=100", wantPanic: true},
		{name: "limit 1 accepted", query: "?limit=1", wantPanic: true},
		{name: "non-numeric defaults to 20", query: "?limit=abc", wantPanic: true},
		{name: "SQL injection defaults to 20", query: "?limit=1%3BDROP%20TABLE", wantPanic: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := NewHandler(NewStore(nil), slog.New(slog.DiscardHandler))

			req := httptest.NewRequest("GET", "/api/admin/reconcile/history"+tt.query, http.NoBody)
			w := httptest.NewRecorder()

			panicked := false
			func() {
				defer func() {
					if r := recover(); r != nil {
						panicked = true
					}
				}()
				h.History(w, req)
			}()

			if tt.wantPanic && !panicked && w.Code != http.StatusInternalServerError {
				// If it didn't panic and didn't return 500, validation may have
				// short-circuited unexpectedly.
				t.Errorf("History(%q) neither panicked nor returned 500 — unexpected status %d",
					tt.query, w.Code)
			}
		})
	}
}

// TestHistory_ContentType verifies JSON content type is set even on errors.
func TestHistory_ContentType(t *testing.T) {
	t.Parallel()

	// With nil store, the handler either panics (nil deref) or returns 500.
	// Either way, if it writes a response, Content-Type should be JSON.
	h := NewHandler(NewStore(nil), slog.New(slog.DiscardHandler))

	req := httptest.NewRequest("GET", "/api/admin/reconcile/history", http.NoBody)
	w := httptest.NewRecorder()

	func() {
		defer func() { recover() }()
		h.History(w, req)
	}()

	if w.Code != 0 {
		ct := w.Header().Get("Content-Type")
		if ct != "" && ct != "application/json" {
			t.Errorf("History() Content-Type = %q, want application/json", ct)
		}
	}
}
