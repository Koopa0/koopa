package stats

// Tests for internal/stats.
//
// Scope:
//   - computeAreaDrift: pure business logic — division-by-zero guards, empty maps,
//     single-side data (goals but no events, events but no goals), sort order.
//   - Handler.Overview / Handler.Drift / Handler.Learning: HTTP handler tests via
//     httptest with a stub db.DBTX that controls which queries succeed or fail.
//   - days param parsing in Handler.Drift: boundary clamping (0, negative, >90, exact
//     boundaries 1 and 90) plus a fuzz test for the raw string path.
//
// Integration tests (real DB via testcontainers) are out of scope here.
// The store-level SQL is exercised by the handler tests through the stub DBTX,
// which validates the control-flow paths inside the store methods without a live DB.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/koopa0/blog-backend/internal/api"
)

// ── computeAreaDrift unit tests ────────────────────────────────────────────────

func TestComputeAreaDrift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		goalsByArea  map[string]int
		totalGoals   int
		eventsByArea map[string]int
		totalEvents  int
		wantLen      int
		wantAreas    []AreaDrift // checked with cmpopts.EquateApprox for floats
	}{
		{
			name:         "empty both sides — no areas",
			goalsByArea:  map[string]int{},
			totalGoals:   0,
			eventsByArea: map[string]int{},
			totalEvents:  0,
			wantLen:      0,
			wantAreas:    []AreaDrift{},
		},
		{
			name:         "goals only, no events — event percent is 0, drift is negative goal pct",
			goalsByArea:  map[string]int{"backend": 2},
			totalGoals:   2,
			eventsByArea: map[string]int{},
			totalEvents:  0,
			wantLen:      1,
			wantAreas: []AreaDrift{
				{Area: "backend", ActiveGoals: 2, EventCount: 0,
					GoalPercent: 100.0, EventPercent: 0, DriftPercent: -100.0},
			},
		},
		{
			name:         "events only, no goals — goal percent is 0, drift is positive event pct",
			goalsByArea:  map[string]int{},
			totalGoals:   0,
			eventsByArea: map[string]int{"frontend": 5},
			totalEvents:  5,
			wantLen:      1,
			wantAreas: []AreaDrift{
				{Area: "frontend", ActiveGoals: 0, EventCount: 5,
					GoalPercent: 0, EventPercent: 100.0, DriftPercent: 100.0},
			},
		},
		{
			name:         "zero totals with populated maps — no division, all percents are 0",
			goalsByArea:  map[string]int{"a": 3},
			totalGoals:   0, // caller passes 0 — pathological but must not panic
			eventsByArea: map[string]int{"a": 7},
			totalEvents:  0,
			wantLen:      1,
			wantAreas: []AreaDrift{
				{Area: "a", ActiveGoals: 3, EventCount: 7,
					GoalPercent: 0, EventPercent: 0, DriftPercent: 0},
			},
		},
		{
			name:         "balanced distribution — drift close to zero",
			goalsByArea:  map[string]int{"go": 1, "rust": 1},
			totalGoals:   2,
			eventsByArea: map[string]int{"go": 1, "rust": 1},
			totalEvents:  2,
			wantLen:      2,
			wantAreas: []AreaDrift{
				{Area: "go", ActiveGoals: 1, EventCount: 1, GoalPercent: 50, EventPercent: 50, DriftPercent: 0},
				{Area: "rust", ActiveGoals: 1, EventCount: 1, GoalPercent: 50, EventPercent: 50, DriftPercent: 0},
			},
		},
		{
			name:         "sorted by absolute drift descending",
			goalsByArea:  map[string]int{"a": 1, "b": 1, "c": 1},
			totalGoals:   3,
			eventsByArea: map[string]int{"a": 3, "b": 0, "c": 0},
			totalEvents:  3,
			// a: goal=33.3, event=100 → drift=+66.7  abs=66.7
			// b: goal=33.3, event=0   → drift=-33.3  abs=33.3
			// c: goal=33.3, event=0   → drift=-33.3  abs=33.3
			// a must come first; b and c tied (both at abs 33.3)
			wantLen: 3,
			// We only check the first element here; the equal pair can be in any order.
			wantAreas: nil, // custom check below
		},
		{
			name:         "disjoint areas — union is taken",
			goalsByArea:  map[string]int{"ai": 2},
			totalGoals:   2,
			eventsByArea: map[string]int{"ops": 3},
			totalEvents:  3,
			wantLen:      2,
			wantAreas: []AreaDrift{
				{Area: "ai", ActiveGoals: 2, EventCount: 0, GoalPercent: 100, EventPercent: 0, DriftPercent: -100},
				{Area: "ops", ActiveGoals: 0, EventCount: 3, GoalPercent: 0, EventPercent: 100, DriftPercent: 100},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := computeAreaDrift(tt.goalsByArea, tt.totalGoals, tt.eventsByArea, tt.totalEvents)

			if len(got) != tt.wantLen {
				t.Fatalf("computeAreaDrift() len = %d, want %d; got %+v", len(got), tt.wantLen, got)
			}

			// Special case: sorted-by-drift test only checks first element.
			if tt.name == "sorted by absolute drift descending" {
				if got[0].Area != "a" {
					t.Errorf("computeAreaDrift() first area = %q, want %q", got[0].Area, "a")
				}
				if math.Abs(got[0].DriftPercent-66.666) > 0.1 {
					t.Errorf("computeAreaDrift() first drift = %f, want ~66.7", got[0].DriftPercent)
				}
				return
			}

			if tt.wantAreas == nil {
				return
			}

			opts := cmp.Options{
				cmpopts.EquateApprox(0, 0.0001), // float tolerance
				cmpopts.SortSlices(func(a, b AreaDrift) bool { return a.Area < b.Area }),
			}
			if diff := cmp.Diff(tt.wantAreas, got, opts...); diff != "" {
				t.Errorf("computeAreaDrift() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestComputeAreaDrift_NoPanic ensures the function never panics on any zero-value
// combination without needing a fuzz harness.
func TestComputeAreaDrift_NoPanic(t *testing.T) {
	t.Parallel()

	cases := []struct {
		goals  map[string]int
		tg     int
		events map[string]int
		te     int
	}{
		{nil, 0, nil, 0},
		{nil, 5, nil, 5},
		{map[string]int{"x": 0}, 0, map[string]int{"x": 0}, 0},
		{map[string]int{"x": 1}, 1, nil, 0},
		{nil, 0, map[string]int{"x": 1}, 1},
	}
	for _, c := range cases {
		// Must not panic.
		_ = computeAreaDrift(c.goals, c.tg, c.events, c.te)
	}
}

// ── Drift percent sort property: result is always sorted by abs(DriftPercent) desc ──

func TestComputeAreaDrift_SortInvariant(t *testing.T) {
	t.Parallel()

	goals := map[string]int{"a": 10, "b": 5, "c": 1}
	events := map[string]int{"a": 1, "b": 10, "c": 5}
	areas := computeAreaDrift(goals, 16, events, 16)

	for i := 1; i < len(areas); i++ {
		prev := math.Abs(areas[i-1].DriftPercent)
		curr := math.Abs(areas[i].DriftPercent)
		if curr > prev {
			t.Errorf("sort invariant violated at index %d: |drift[%d]|=%f > |drift[%d]|=%f",
				i, i, curr, i-1, prev)
		}
	}
}

// ── Stub DBTX implementation ───────────────────────────────────────────────────

// stubDBTX implements db.DBTX. Each method is controlled by a function field so
// individual tests can inject targeted failures or canned results.
type stubDBTX struct {
	queryFn    func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
}

func (s *stubDBTX) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (s *stubDBTX) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if s.queryFn != nil {
		return s.queryFn(ctx, sql, args...)
	}
	return &emptyRows{}, nil
}

func (s *stubDBTX) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if s.queryRowFn != nil {
		return s.queryRowFn(ctx, sql, args...)
	}
	return &zeroRow{}
}

// emptyRows is a pgx.Rows that immediately signals no rows.
type emptyRows struct{}

func (e *emptyRows) Next() bool                    { return false }
func (e *emptyRows) Scan(_ ...any) error           { return nil }
func (e *emptyRows) Err() error                    { return nil }
func (e *emptyRows) Close()                        {}
func (e *emptyRows) CommandTag() pgconn.CommandTag { return pgconn.CommandTag{} }
func (e *emptyRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}
func (e *emptyRows) Values() ([]any, error) { return nil, nil }
func (e *emptyRows) RawValues() [][]byte    { return nil }
func (e *emptyRows) Conn() *pgx.Conn        { return nil }

// zeroRow scans all destination pointers to their zero value.
type zeroRow struct{}

func (z *zeroRow) Scan(dest ...any) error {
	for _, d := range dest {
		switch v := d.(type) {
		case *int:
			*v = 0
		case *int64:
			*v = 0
		case *string:
			*v = ""
		case **string:
			*v = nil
		}
	}
	return nil
}

// errRow always returns a configurable error from Scan.
type errRow struct{ err error }

func (e *errRow) Scan(_ ...any) error { return e.err }

// errRows always returns an error from the first call to Next (via Err).
type errRows struct{ err error }

func (e *errRows) Next() bool                                   { return false }
func (e *errRows) Scan(_ ...any) error                          { return nil }
func (e *errRows) Err() error                                   { return e.err }
func (e *errRows) Close()                                       {}
func (e *errRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (e *errRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (e *errRows) Values() ([]any, error)                       { return nil, nil }
func (e *errRows) RawValues() [][]byte                          { return nil }
func (e *errRows) Conn() *pgx.Conn                              { return nil }

// silentLogger discards all log output from the handler.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ── Handler.Overview tests ─────────────────────────────────────────────────────

func TestHandler_Overview_Success(t *testing.T) {
	t.Parallel()

	dbtx := &stubDBTX{
		// All Query calls return empty rows — store accumulates zeros.
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return &emptyRows{}, nil
		},
		// All QueryRow calls scan zeros — no error.
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &zeroRow{}
		},
	}

	h := NewHandler(NewStore(dbtx), silentLogger())

	req := httptest.NewRequest(http.MethodGet, "/api/admin/stats", nil)
	w := httptest.NewRecorder()
	h.Overview(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Overview() status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp api.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Data == nil {
		t.Fatal("Overview() response.data is nil, want overview object")
	}
}

func TestHandler_Overview_StoreError(t *testing.T) {
	t.Parallel()

	boom := errors.New("db unavailable")

	// Make every Query call fail — errgroup will return this error.
	dbtx := &stubDBTX{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, boom
		},
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &errRow{err: boom}
		},
	}

	h := NewHandler(NewStore(dbtx), silentLogger())

	req := httptest.NewRequest(http.MethodGet, "/api/admin/stats", nil)
	w := httptest.NewRecorder()
	h.Overview(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Overview() on DB error: status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	assertErrorCode(t, w, "INTERNAL")
}

// ── Handler.Drift tests ────────────────────────────────────────────────────────

func TestHandler_Drift_DaysParamClamping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		query    string
		wantDays int // verified via DriftReport.Period field
	}{
		{name: "default — no param", query: "", wantDays: 30},
		{name: "valid 7", query: "days=7", wantDays: 7},
		{name: "valid 90 — upper boundary", query: "days=90", wantDays: 90},
		{name: "valid 1 — lower boundary", query: "days=1", wantDays: 1},
		{name: "0 — rejected, falls back to 30", query: "days=0", wantDays: 30},
		{name: "negative — rejected, falls back to 30", query: "days=-5", wantDays: 30},
		{name: "91 — exceeds max, falls back to 30", query: "days=91", wantDays: 30},
		{name: "non-numeric — rejected, falls back to 30", query: "days=abc", wantDays: 30},
		{name: "empty string — falls back to 30", query: "days=", wantDays: 30},
		{name: "float string — rejected, falls back to 30", query: "days=7.5", wantDays: 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The Drift store method calls queryGoalsByArea and queryEventsByArea.
			// Both use Query; return empty rows so the handler succeeds and we can
			// inspect the period string in the response.
			dbtx := &stubDBTX{
				queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
					return &emptyRows{}, nil
				},
			}

			h := NewHandler(NewStore(dbtx), silentLogger())

			url := "/api/admin/stats/drift"
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()
			h.Drift(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("Drift(%q) status = %d, want %d; body: %s",
					tt.query, w.Code, http.StatusOK, w.Body.String())
			}

			var resp struct {
				Data DriftReport `json:"data"`
			}
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decoding response: %v", err)
			}

			wantPeriod := fmt.Sprintf("last %d days", tt.wantDays)
			if resp.Data.Period != wantPeriod {
				t.Errorf("Drift(%q).Period = %q, want %q", tt.query, resp.Data.Period, wantPeriod)
			}
		})
	}
}

func TestHandler_Drift_StoreError(t *testing.T) {
	t.Parallel()

	boom := errors.New("query failed")
	dbtx := &stubDBTX{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, boom
		},
	}

	h := NewHandler(NewStore(dbtx), silentLogger())

	req := httptest.NewRequest(http.MethodGet, "/api/admin/stats/drift", nil)
	w := httptest.NewRecorder()
	h.Drift(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Drift() on DB error: status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	assertErrorCode(t, w, "INTERNAL")
}

// ── Handler.Learning tests ─────────────────────────────────────────────────────

func TestHandler_Learning_Success(t *testing.T) {
	t.Parallel()

	dbtx := &stubDBTX{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return &emptyRows{}, nil
		},
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &zeroRow{}
		},
	}

	h := NewHandler(NewStore(dbtx), silentLogger())

	req := httptest.NewRequest(http.MethodGet, "/api/admin/stats/learning", nil)
	w := httptest.NewRecorder()
	h.Learning(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Learning() status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp struct {
		Data LearningDashboard `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding Learning() response: %v", err)
	}

	// Empty DB — all counts must be zero, trend stable, top tags empty (not nil).
	if resp.Data.Notes.Total != 0 {
		t.Errorf("Learning().Notes.Total = %d, want 0", resp.Data.Notes.Total)
	}
	if resp.Data.Activity.Trend != "stable" {
		t.Errorf("Learning().Activity.Trend = %q, want %q", resp.Data.Activity.Trend, "stable")
	}
	if resp.Data.TopTags == nil {
		t.Error("Learning().TopTags is nil, want empty slice")
	}
}

func TestHandler_Learning_AllQueriesFail_ReturnsError(t *testing.T) {
	t.Parallel()

	// All three sub-queries (learningNoteGrowth, learningWeeklyActivity, learningTopTags)
	// rely on QueryRow or Query. Make both fail so hasData stays false and the store
	// returns the "all learning queries failed" error.
	boom := errors.New("total outage")
	dbtx := &stubDBTX{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return nil, boom
		},
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &errRow{err: boom}
		},
	}

	h := NewHandler(NewStore(dbtx), silentLogger())

	req := httptest.NewRequest(http.MethodGet, "/api/admin/stats/learning", nil)
	w := httptest.NewRecorder()
	h.Learning(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Learning() all-fail: status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	assertErrorCode(t, w, "INTERNAL")
}

func TestHandler_Learning_PartialFailure_StillSucceeds(t *testing.T) {
	t.Parallel()

	// learningNoteGrowth uses QueryRow first, then Query.
	// Let QueryRow succeed (zeros) but Query fail.
	// learningWeeklyActivity uses QueryRow — also succeeds.
	// learningTopTags uses Query — fails.
	// hasData should be true (at least learningNoteGrowth + learningWeeklyActivity
	// contributed some data via QueryRow), so the handler returns 200.
	boom := errors.New("tags table missing")
	dbtx := &stubDBTX{
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			// Fail only the tags query (contains "obsidian_note_tags").
			if strings.Contains(sql, "obsidian_note_tags") {
				return nil, boom
			}
			// The by-type breakdown query (contains "combined") also returns error
			// to exercise the partial-failure branch in learningNoteGrowth.
			if strings.Contains(sql, "combined") {
				return nil, boom
			}
			return &emptyRows{}, nil
		},
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &zeroRow{}
		},
	}

	h := NewHandler(NewStore(dbtx), silentLogger())

	req := httptest.NewRequest(http.MethodGet, "/api/admin/stats/learning", nil)
	w := httptest.NewRecorder()
	h.Learning(w, req)

	// learningWeeklyActivity succeeds via QueryRow so hasData = true.
	if w.Code != http.StatusOK {
		t.Fatalf("Learning() partial-fail: status = %d, want %d; body: %s",
			w.Code, http.StatusOK, w.Body.String())
	}
}

// ── Drift days param fuzz test ─────────────────────────────────────────────────

// FuzzDriftDaysParam verifies that the days-parsing logic in Handler.Drift never
// panics and always falls back safely on arbitrary input.
func FuzzDriftDaysParam(f *testing.F) {
	// Seed corpus — boundaries and tricky inputs.
	f.Add("30")
	f.Add("1")
	f.Add("90")
	f.Add("0")
	f.Add("-1")
	f.Add("91")
	f.Add("")
	f.Add("abc")
	f.Add("7.5")
	f.Add("1e2")
	f.Add("9999999999999999999") // overflow
	f.Add(" 30 ")                // whitespace
	f.Add("30 ")                 // trailing space — not parseable by strconv.Atoi

	dbtx := &stubDBTX{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return &emptyRows{}, nil
		},
	}
	h := NewHandler(NewStore(dbtx), silentLogger())

	f.Fuzz(func(t *testing.T, rawDays string) {
		// httptest.NewRequest panics when the URL contains bytes that make
		// it structurally invalid (spaces, control chars). Use
		// url.QueryEscape so the fuzz corpus can exercise arbitrary byte
		// sequences through the handler's Atoi / bounds-check path without
		// triggering the HTTP library's URL validator.
		escaped := url.QueryEscape(rawDays)
		req := httptest.NewRequest(http.MethodGet, "/api/admin/stats/drift?days="+escaped, nil)
		w := httptest.NewRecorder()

		// Must not panic.
		h.Drift(w, req)

		// The handler must always return a valid HTTP status.
		if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
			t.Errorf("unexpected status %d for days=%q", w.Code, rawDays)
		}

		// If successful, Period must match "last N days" where N is in [1, 90].
		if w.Code == http.StatusOK {
			var resp struct {
				Data DriftReport `json:"data"`
			}
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decoding fuzz response: %v", err)
			}
			// Period format: "last N days" — N must be between 1 and 90.
			var n int
			if _, err := fmt.Sscanf(resp.Data.Period, "last %d days", &n); err != nil {
				t.Errorf("Period %q doesn't match 'last N days': %v", resp.Data.Period, err)
				return
			}
			if n < 1 || n > 90 {
				t.Errorf("Period N = %d, want [1, 90]", n)
			}

			// Verify that non-parseable or out-of-range inputs always produce days=30.
			d, err := strconv.Atoi(strings.TrimSpace(rawDays))
			outOfRange := err != nil || d <= 0 || d > 90
			if outOfRange && n != 30 {
				t.Errorf("out-of-range input %q produced days=%d, want 30", rawDays, n)
			}
		}
	})
}

// ── helpers ────────────────────────────────────────────────────────────────────

// assertErrorCode decodes the response body and asserts the error code field.
func assertErrorCode(t *testing.T, w *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	var body api.ErrorBody
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	if diff := cmp.Diff(wantCode, body.Error.Code); diff != "" {
		t.Errorf("error code mismatch (-want +got):\n%s", diff)
	}
}
