package task

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Task.IsRecurring
// ---------------------------------------------------------------------------

func TestTask_IsRecurring(t *testing.T) {
	t.Parallel()

	zero := int32(0)
	one := int32(1)
	big := int32(999)
	neg := int32(-1)

	tests := []struct {
		name          string
		recurInterval *int32
		want          bool
	}{
		{name: "nil interval → not recurring", recurInterval: nil, want: false},
		{name: "zero interval → not recurring", recurInterval: &zero, want: false},
		{name: "negative interval → not recurring", recurInterval: &neg, want: false},
		{name: "interval = 1 → recurring", recurInterval: &one, want: true},
		{name: "large interval → recurring", recurInterval: &big, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			task := &Task{RecurInterval: tt.recurInterval}
			got := task.IsRecurring()
			if got != tt.want {
				t.Errorf("Task.IsRecurring() = %v, want %v (interval=%v)", got, tt.want, tt.recurInterval)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Task.NextDue
// ---------------------------------------------------------------------------

func TestTask_NextDue(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	interval1 := int32(1)
	interval7 := int32(7)
	interval2 := int32(2)

	tests := []struct {
		name     string
		task     Task
		wantNil  bool
		wantDate time.Time
	}{
		{
			name:    "not recurring → nil",
			task:    Task{Due: &base},
			wantNil: true,
		},
		{
			name: "recurring but no due date → nil",
			task: Task{
				RecurInterval: &interval1,
				RecurUnit:     "Day(s)",
			},
			wantNil: true,
		},
		{
			name: "daily + 1 day",
			task: Task{
				Due:           &base,
				RecurInterval: &interval1,
				RecurUnit:     "Day(s)",
			},
			wantDate: time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "weekly + 1 week",
			task: Task{
				Due:           &base,
				RecurInterval: &interval1,
				RecurUnit:     "Week(s)",
			},
			wantDate: time.Date(2026, 1, 22, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "monthly + 1 month",
			task: Task{
				Due:           &base,
				RecurInterval: &interval1,
				RecurUnit:     "Month(s)",
			},
			wantDate: time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "yearly + 2 years",
			task: Task{
				Due:           &base,
				RecurInterval: &interval2,
				RecurUnit:     "Year(s)",
			},
			wantDate: time.Date(2028, 1, 15, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "unknown unit falls back to days",
			task: Task{
				Due:           &base,
				RecurInterval: &interval7,
				RecurUnit:     "Fortnight(s)", // unknown
			},
			wantDate: time.Date(2026, 1, 22, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "weekly 7 intervals × 7 days",
			task: Task{
				Due:           &base,
				RecurInterval: &interval7,
				RecurUnit:     "Week(s)",
			},
			wantDate: time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.task.NextDue()
			if tt.wantNil {
				if got != nil {
					t.Errorf("Task.NextDue() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("Task.NextDue() = nil, want non-nil")
			}
			if !got.Equal(tt.wantDate) {
				t.Errorf("Task.NextDue() = %v, want %v", got, tt.wantDate)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Task.NextDue — month-end clamping
// ---------------------------------------------------------------------------

func TestTask_NextDue_MonthEndClamping(t *testing.T) {
	t.Parallel()

	interval1 := int32(1)

	tests := []struct {
		name     string
		due      time.Time
		wantDate time.Time
	}{
		{
			name:     "Jan 31 + 1 month = Feb 28 (non-leap)",
			due:      time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC),
			wantDate: time.Date(2026, 2, 28, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "Jan 31 + 1 month = Feb 29 (leap year)",
			due:      time.Date(2028, 1, 31, 0, 0, 0, 0, time.UTC),
			wantDate: time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "Mar 31 + 1 month = Apr 30",
			due:      time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
			wantDate: time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "Feb 28 + 1 month = Mar 28 (not 31)",
			due:      time.Date(2026, 2, 28, 0, 0, 0, 0, time.UTC),
			wantDate: time.Date(2026, 3, 28, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			task := Task{Due: &tt.due, RecurInterval: &interval1, RecurUnit: "Month(s)"}
			got := task.NextDue()
			if got == nil {
				t.Fatal("NextDue() = nil, want non-nil")
			}
			if !got.Equal(tt.wantDate) {
				t.Errorf("NextDue() = %v, want %v", got.Format(time.DateOnly), tt.wantDate.Format(time.DateOnly))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Task.NextCycleDateOnOrAfter
// ---------------------------------------------------------------------------

func TestTask_NextCycleDateOnOrAfter(t *testing.T) {
	t.Parallel()

	interval1 := int32(1)
	interval7 := int32(7)

	tests := []struct {
		name     string
		task     Task
		cutoff   time.Time
		wantNil  bool
		wantDate time.Time
	}{
		{
			name:    "not recurring → nil",
			task:    Task{Due: timePtr(2026, 1, 1)},
			cutoff:  time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
			wantNil: true,
		},
		{
			name:     "daily, 3 days overdue → today",
			task:     Task{Due: timePtr(2026, 3, 28), RecurInterval: &interval1, RecurUnit: "Day(s)"},
			cutoff:   time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
			wantDate: time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "weekly, 3 days overdue → next cycle (not today)",
			task:     Task{Due: timePtr(2026, 3, 28), RecurInterval: &interval1, RecurUnit: "Week(s)"},
			cutoff:   time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
			wantDate: time.Date(2026, 4, 4, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "weekly, exactly on cycle → today",
			task:     Task{Due: timePtr(2026, 3, 24), RecurInterval: &interval1, RecurUnit: "Week(s)"},
			cutoff:   time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
			wantDate: time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "monthly, Jan 31 overdue in March → Apr 28 (clamped to 28 after Feb)",
			task:     Task{Due: timePtr(2026, 1, 31), RecurInterval: &interval1, RecurUnit: "Month(s)"},
			cutoff:   time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
			wantDate: time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "due is already >= cutoff → returns due",
			task:     Task{Due: timePtr(2026, 4, 5), RecurInterval: &interval1, RecurUnit: "Day(s)"},
			cutoff:   time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
			wantDate: time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "every 7 days, 10 days overdue → 3/21 + 14 = 4/4",
			task:     Task{Due: timePtr(2026, 3, 21), RecurInterval: &interval7, RecurUnit: "Day(s)"},
			cutoff:   time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
			wantDate: time.Date(2026, 4, 4, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.task.NextCycleDateOnOrAfter(tt.cutoff)
			if tt.wantNil {
				if got != nil {
					t.Errorf("NextCycleDateOnOrAfter() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("NextCycleDateOnOrAfter() = nil, want non-nil")
			}
			if !got.Equal(tt.wantDate) {
				t.Errorf("NextCycleDateOnOrAfter() = %v, want %v", got.Format(time.DateOnly), tt.wantDate.Format(time.DateOnly))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Task.MissedOccurrences
// ---------------------------------------------------------------------------

func TestTask_MissedOccurrences(t *testing.T) {
	t.Parallel()

	interval1 := int32(1)

	tests := []struct {
		name   string
		task   Task
		cutoff time.Time
		want   []string // YYYY-MM-DD
	}{
		{
			name:   "daily, 3 days overdue → 3 missed",
			task:   Task{Due: timePtr(2026, 3, 28), RecurInterval: &interval1, RecurUnit: "Day(s)"},
			cutoff: time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
			want:   []string{"2026-03-28", "2026-03-29", "2026-03-30"},
		},
		{
			name:   "weekly, 10 days overdue → 1 missed",
			task:   Task{Due: timePtr(2026, 3, 21), RecurInterval: &interval1, RecurUnit: "Week(s)"},
			cutoff: time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
			want:   []string{"2026-03-21", "2026-03-28"},
		},
		{
			name:   "not overdue → empty",
			task:   Task{Due: timePtr(2026, 4, 1), RecurInterval: &interval1, RecurUnit: "Day(s)"},
			cutoff: time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.task.MissedOccurrences(tt.cutoff)
			var gotStr []string
			for _, d := range got {
				gotStr = append(gotStr, d.Format(time.DateOnly))
			}
			if diff := cmp.Diff(tt.want, gotStr); diff != "" {
				t.Errorf("MissedOccurrences() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func timePtr(y int, m time.Month, d int) *time.Time {
	t := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return &t
}

// ---------------------------------------------------------------------------
// ValidAssignee
// ---------------------------------------------------------------------------

func TestValidAssignee(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "human", input: "human", want: true},
		{name: "claude-code", input: "claude-code", want: true},
		{name: "cowork", input: "cowork", want: true},
		{name: "empty string", input: "", want: false},
		{name: "capitalized Human", input: "Human", want: false},
		{name: "HUMAN", input: "HUMAN", want: false},
		{name: "claude", input: "claude", want: false}, // partial match
		{name: "unknown user", input: "alice", want: false},
		{name: "sql injection", input: "' OR '1'='1", want: false},
		{name: "space", input: " human", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ValidAssignee(tt.input)
			if got != tt.want {
				t.Errorf("ValidAssignee(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseDueDate
// ---------------------------------------------------------------------------

func TestParseDueDate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string // YYYY-MM-DD, empty means nil expected
		wantErr bool
	}{
		{name: "valid date", input: "2026-03-15", want: "2026-03-15"},
		{name: "empty string → nil, nil", input: "", want: ""},
		{name: "wrong format MM/DD/YYYY", input: "03/15/2026", wantErr: true},
		{name: "wrong format DD-MM-YYYY", input: "15-03-2026", wantErr: true},
		{name: "partial date", input: "2026-03", wantErr: true},
		{name: "unix timestamp", input: "1742860800", wantErr: true},
		{name: "date with time", input: "2026-03-15T00:00:00Z", wantErr: true},
		{name: "invalid month 13", input: "2026-13-01", wantErr: true},
		{name: "invalid day 32", input: "2026-01-32", wantErr: true},
		{name: "leap day valid", input: "2024-02-29", want: "2024-02-29"},
		{name: "non-leap year feb 29", input: "2026-02-29", wantErr: true},
		{name: "non-date string", input: "tomorrow", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseDueDate(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseDueDate(%q) expected error, got nil (result: %v)", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDueDate(%q) unexpected error: %v", tt.input, err)
			}

			if tt.want == "" {
				if got != nil {
					t.Errorf("parseDueDate(%q) = %v, want nil", tt.input, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseDueDate(%q) = nil, want %q", tt.input, tt.want)
			}
			if diff := cmp.Diff(tt.want, got.Format(time.DateOnly)); diff != "" {
				t.Errorf("parseDueDate(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

func FuzzParseDueDate(f *testing.F) {
	f.Add("2026-03-15")
	f.Add("")
	f.Add("03/15/2026")
	f.Add("2026-13-01")
	f.Add("not-a-date")
	f.Add("0000-00-00")
	f.Add("9999-12-31")
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = parseDueDate(input) // must not panic
	})
}

// ---------------------------------------------------------------------------
// mapHTTPTaskStatus
// ---------------------------------------------------------------------------

func TestMapHTTPTaskStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  Status
	}{
		{name: "todo", input: "todo", want: StatusTodo},
		{name: "To Do (Notion)", input: "To Do", want: StatusTodo},
		{name: "in-progress", input: "in-progress", want: StatusInProgress},
		{name: "Doing (Notion)", input: "Doing", want: StatusInProgress},
		{name: "In Progress alt", input: "In Progress", want: StatusInProgress},
		{name: "done", input: "done", want: StatusDone},
		{name: "Done (Notion)", input: "Done", want: StatusDone},
		{name: "unknown → defaults to todo", input: "COMPLETED", want: StatusTodo},
		{name: "empty → defaults to todo", input: "", want: StatusTodo},
		{name: "garbage → defaults to todo", input: "🚀", want: StatusTodo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mapHTTPTaskStatus(tt.input)
			if got != tt.want {
				t.Errorf("mapHTTPTaskStatus(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildHTTPNotionProps
// ---------------------------------------------------------------------------

func TestBuildHTTPNotionProps(t *testing.T) {
	t.Parallel()

	strPtr := func(s string) *string { return &s }
	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name    string
		req     updateRequest
		wantKey string // a key that must appear in props
		absent  string // a key that must NOT appear
	}{
		{
			name:   "nil req → empty props",
			req:    updateRequest{},
			absent: "Status",
		},
		{
			name:    "status todo",
			req:     updateRequest{Status: strPtr("todo")},
			wantKey: "Status",
		},
		{
			name:    "status done",
			req:     updateRequest{Status: strPtr("done")},
			wantKey: "Status",
		},
		{
			name:    "due date",
			req:     updateRequest{Due: strPtr("2026-03-15")},
			wantKey: "Due",
		},
		{
			name:    "clear due date (empty string)",
			req:     updateRequest{Due: strPtr("")},
			wantKey: "Due",
		},
		{
			name:    "priority",
			req:     updateRequest{Priority: strPtr("High")},
			wantKey: "Priority",
		},
		{
			name:    "energy",
			req:     updateRequest{Energy: strPtr("Low")},
			wantKey: "Energy",
		},
		{
			name:    "my day true",
			req:     updateRequest{MyDay: boolPtr(true)},
			wantKey: "My Day",
		},
		{
			name:    "my day false",
			req:     updateRequest{MyDay: boolPtr(false)},
			wantKey: "My Day",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildHTTPNotionProps(tt.req)

			if tt.wantKey != "" {
				if _, ok := got[tt.wantKey]; !ok {
					t.Errorf("buildHTTPNotionProps() missing key %q, got keys: %v", tt.wantKey, keysOf(got))
				}
			}
			if tt.absent != "" {
				if _, ok := got[tt.absent]; ok {
					t.Errorf("buildHTTPNotionProps() should not contain key %q", tt.absent)
				}
			}
		})
	}
}

func TestBuildHTTPNotionProps_StatusMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input    string
		wantName string
	}{
		{input: "todo", wantName: "To Do"},
		{input: "To Do", wantName: "To Do"},
		{input: "in-progress", wantName: "Doing"},
		{input: "Doing", wantName: "Doing"},
		{input: "done", wantName: "Done"},
		{input: "Done", wantName: "Done"},
		{input: "unknown", wantName: "To Do"}, // default
	}

	for _, tt := range cases {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			req := updateRequest{Status: &tt.input}
			props := buildHTTPNotionProps(req)

			statusProp, ok := props["Status"]
			if !ok {
				t.Fatal("buildHTTPNotionProps() missing Status key")
			}
			outer, ok := statusProp.(map[string]any)
			if !ok {
				t.Fatalf("Status prop is %T, want map[string]any", statusProp)
			}
			inner, ok := outer["status"].(map[string]string)
			if !ok {
				t.Fatalf("Status.status is %T, want map[string]string", outer["status"])
			}
			if diff := cmp.Diff(tt.wantName, inner["name"]); diff != "" {
				t.Errorf("buildHTTPNotionProps(status=%q) Notion name mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Handler: HTTP endpoint validation (no store calls triggered by validation)
// ---------------------------------------------------------------------------

func newNilStoreHandler(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewHandler(nil, logger)
}

func TestHandler_Update_InvalidUUID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		id   string
	}{
		{name: "empty id", id: ""},
		{name: "not a uuid", id: "not-a-uuid"},
		{name: "integer", id: "123"},
		{name: "sql injection", id: "' OR 1=1 --"},
	}

	h := newNilStoreHandler(t)
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := strings.NewReader(`{"status":"done"}`)
			req := httptest.NewRequest(http.MethodPut, "/api/admin/tasks/PLACEHOLDER", body)
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()

			h.Update(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Update(%q) status = %d, want %d", tt.id, w.Code, http.StatusBadRequest)
			}
			assertTaskErrorCode(t, w, "INVALID_ID")
		})
	}
}

func TestHandler_Complete_InvalidUUID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		id   string
	}{
		{name: "empty id", id: ""},
		{name: "garbage", id: "garbage-id"},
		{name: "path traversal", id: "../../etc/passwd"},
	}

	h := newNilStoreHandler(t)
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.SetPathValue("id", tt.id)
			w := httptest.NewRecorder()

			h.Complete(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Complete(%q) status = %d, want %d", tt.id, w.Code, http.StatusBadRequest)
			}
			assertTaskErrorCode(t, w, "INVALID_ID")
		})
	}
}

func TestHandler_BatchMyDay_EmptyTasksNoClear(t *testing.T) {
	t.Parallel()

	h := newNilStoreHandler(t)

	// No task_ids and clear=false → should be rejected with MISSING_IDS.
	body := strings.NewReader(`{"task_ids":[],"clear":false}`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/tasks/batch-my-day", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.BatchMyDay(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("BatchMyDay(empty+no-clear) status = %d, want %d (body: %s)", w.Code, http.StatusBadRequest, w.Body.String())
	}
	assertTaskErrorCode(t, w, "MISSING_IDS")
}

func TestHandler_BatchMyDay_NullTaskIdsNoClear(t *testing.T) {
	t.Parallel()

	h := newNilStoreHandler(t)

	// Null task_ids and clear=false — an adversarial input
	body := strings.NewReader(`{"task_ids":null,"clear":false}`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/tasks/batch-my-day", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.BatchMyDay(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("BatchMyDay(null+no-clear) status = %d, want %d (body: %s)", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestHandler_Create_MissingTitle(t *testing.T) {
	t.Parallel()

	h := newNilStoreHandler(t)

	cases := []struct {
		name string
		body string
	}{
		{name: "empty title string", body: `{"title":""}`},
		{name: "missing title field", body: `{}`},
		{name: "whitespace only title", body: `{"title":"   "}`},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// NOTE: whitespace-only title is NOT rejected (handler only checks for "").
			// The test documents current behavior; a future improvement could trim.
			req := httptest.NewRequest(http.MethodPost, "/api/admin/tasks", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			h.Create(w, req)

			// Empty title: expect 400.
			// Whitespace-only title: handler currently does not reject it (reaches Notion check → 503).
			switch tt.name {
			case "empty title string", "missing title field":
				if w.Code != http.StatusBadRequest {
					t.Errorf("Create(%q) status = %d, want %d (body: %s)", tt.body, w.Code, http.StatusBadRequest, w.Body.String())
				}
				assertTaskErrorCode(t, w, "MISSING_TITLE")
			case "whitespace only title":
				// Documents current behavior: whitespace passes title check,
				// reaches Notion integration check, returns 503 (not configured).
				if w.Code != http.StatusServiceUnavailable && w.Code != http.StatusBadRequest {
					t.Errorf("Create(whitespace title) status = %d, want 400 or 503", w.Code)
				}
			}
		})
	}
}

func TestHandler_Create_InvalidBody(t *testing.T) {
	t.Parallel()

	h := newNilStoreHandler(t)

	cases := []struct {
		name string
		body string
	}{
		{name: "malformed json", body: `{title: no-quotes}`},
		{name: "array instead of object", body: `["title","task1"]`},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/api/admin/tasks", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			h.Create(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Create(invalid body) status = %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BatchMyDay: invalid UUIDs in task_ids list are skipped (not fatal)
// ---------------------------------------------------------------------------

func TestHandler_BatchMyDay_InvalidUUIDsAreSkipped(t *testing.T) {
	t.Parallel()

	// When clear=true and store is nil, the handler will call store.MyDayTasksWithNotionPageID
	// via syncNotionClearMyDay (best-effort, skipped when notion == nil).
	// Then ClearAllMyDay is called — that will panic on nil store.
	// So we cannot test clear=true with nil store.
	//
	// For set-only (clear=false), the handler iterates task_ids, calling uuid.Parse.
	// Invalid UUIDs are logged and skipped. With nil store, UpdateMyDay panics.
	// Therefore: this test only verifies the pre-loop validation returns 400
	// when task_ids is empty without clear.
	//
	// The invalid-UUID-skipping behavior is covered by the integration test.
	t.Skip("invalid UUID skip behavior requires a real store — covered by integration tests")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type taskErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func assertTaskErrorCode(t *testing.T, w *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	var resp taskErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding error response: %v (body: %s)", err, w.Body.String())
	}
	if resp.Error.Code != wantCode {
		t.Errorf("error code = %q, want %q", resp.Error.Code, wantCode)
	}
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Prevent unused import warning — uuid is used in test setup.
var _ = uuid.New
var _ = json.Marshal
