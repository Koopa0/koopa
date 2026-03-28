package mcpserver

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/task"
)

// strPtr returns a pointer to s.
//
//go:fix inline
func strPtr(s string) *string { return new(s) }

// int32Ptr returns a pointer to v.
//
//go:fix inline
func int32Ptr(v int32) *int32 { return new(v) }

func TestToSearchEntries(t *testing.T) {
	t.Parallel()

	title1 := "First Note"
	type1 := "til"

	tests := []struct {
		name        string
		textResults []note.SearchResult
		want        []searchResultEntry
	}{
		{
			name:        "empty input",
			textResults: []note.SearchResult{},
			want:        []searchResultEntry{},
		},
		{
			name: "single result",
			textResults: []note.SearchResult{
				{Note: note.Note{ID: 1, FilePath: "notes/first.md", Title: &title1, Type: &type1}, Rank: 0.8},
			},
			want: []searchResultEntry{
				{Note: note.Note{ID: 1, FilePath: "notes/first.md", Title: &title1, Type: &type1}, Score: float64(float32(0.8))},
			},
		},
		{
			name: "multiple results preserve order",
			textResults: []note.SearchResult{
				{Note: note.Note{ID: 10}, Rank: 1.0},
				{Note: note.Note{ID: 20}, Rank: 0.5},
				{Note: note.Note{ID: 30}, Rank: 0.1},
			},
			want: []searchResultEntry{
				{Note: note.Note{ID: 10}, Score: float64(float32(1.0))},
				{Note: note.Note{ID: 20}, Score: float64(float32(0.5))},
				{Note: note.Note{ID: 30}, Score: float64(float32(0.1))},
			},
		},
		{
			name: "nil optional fields remain nil",
			textResults: []note.SearchResult{
				{Note: note.Note{ID: 5, FilePath: "p.md"}, Rank: 0.0},
			},
			want: []searchResultEntry{
				{Note: note.Note{ID: 5, FilePath: "p.md"}, Score: 0.0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := toSearchEntries(tt.textResults)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("toSearchEntries() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestToFilterEntries(t *testing.T) {
	t.Parallel()

	title := "Filter Note"

	tests := []struct {
		name          string
		filterResults []note.Note
		want          []searchResultEntry
	}{
		{
			name:          "empty input",
			filterResults: []note.Note{},
			want:          []searchResultEntry{},
		},
		{
			name: "single note",
			filterResults: []note.Note{
				{ID: 1, FilePath: "notes/a.md", Title: &title},
			},
			want: []searchResultEntry{
				{Note: note.Note{ID: 1, FilePath: "notes/a.md", Title: &title}, Score: 0},
			},
		},
		{
			name: "multiple notes score is always zero",
			filterResults: []note.Note{
				{ID: 1, FilePath: "notes/a.md"},
				{ID: 2, FilePath: "notes/b.md"},
			},
			want: []searchResultEntry{
				{Note: note.Note{ID: 1, FilePath: "notes/a.md"}, Score: 0},
				{Note: note.Note{ID: 2, FilePath: "notes/b.md"}, Score: 0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := toFilterEntries(tt.filterResults)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("toFilterEntries() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestToSearchFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input SearchNotesInput
		want  note.SearchFilter
	}{
		{
			name:  "no filters",
			input: SearchNotesInput{},
			want:  note.SearchFilter{},
		},
		{
			name:  "content_type only",
			input: SearchNotesInput{Type: "til"},
			want:  note.SearchFilter{Type: new("til")},
		},
		{
			name:  "source only",
			input: SearchNotesInput{Source: "leetcode"},
			want:  note.SearchFilter{Source: new("leetcode")},
		},
		{
			name:  "context only",
			input: SearchNotesInput{Context: "my-project"},
			want:  note.SearchFilter{Context: new("my-project")},
		},
		{
			name:  "book only",
			input: SearchNotesInput{Book: "Clean Code"},
			want:  note.SearchFilter{Book: new("Clean Code")},
		},
		{
			name:  "valid date_from",
			input: SearchNotesInput{After: "2024-01-15"},
			want: note.SearchFilter{
				After: new(time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)),
			},
		},
		{
			name:  "valid date_to shifts to start of next day",
			input: SearchNotesInput{Before: "2024-01-20"},
			want: note.SearchFilter{
				Before: new(time.Date(2024, 1, 21, 0, 0, 0, 0, time.UTC)),
			},
		},
		{
			name:  "invalid date_from ignored",
			input: SearchNotesInput{After: "not-a-date"},
			want:  note.SearchFilter{},
		},
		{
			name:  "invalid date_to ignored",
			input: SearchNotesInput{Before: "2024/01/20"},
			want:  note.SearchFilter{},
		},
		{
			name: "all filters combined",
			input: SearchNotesInput{
				Type:    "article",
				Source:  "book",
				Context: "project-x",
				Book:    "DDIA",
				After:   "2024-03-01",
				Before:  "2024-03-31",
			},
			want: note.SearchFilter{
				Type:    new("article"),
				Source:  new("book"),
				Context: new("project-x"),
				Book:    new("DDIA"),
				After:   new(time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)),
				Before:  new(time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := toSearchFilter(&tt.input)
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("toSearchFilter() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestToNoteResult(t *testing.T) {
	t.Parallel()

	title := "My Note"
	noteType := "til"
	ctx := "project-foo"
	src := "book"
	content := "This is the content text that is quite long and should be truncated eventually if it exceeds limits"

	tests := []struct {
		name string
		r    searchResultEntry
		want noteResult
	}{
		{
			name: "full note with all fields",
			r: searchResultEntry{
				Note: note.Note{
					ID:          42,
					FilePath:    "notes/my-note.md",
					Title:       &title,
					Type:        &noteType,
					Context:     &ctx,
					Source:      &src,
					Tags:        []string{"go", "testing"},
					ContentText: &content,
				},
				Score: 0.95,
			},
			want: noteResult{
				ID:       42,
				FilePath: "notes/my-note.md",
				Title:    "My Note",
				Type:     "til",
				Context:  "project-foo",
				Source:   "book",
				Tags:     []string{"go", "testing"},
				Excerpt:  content, // short enough not to be truncated at 200
				Score:    0.95,
			},
		},
		{
			name: "minimal note with nil optional fields",
			r: searchResultEntry{
				Note: note.Note{
					ID:       7,
					FilePath: "notes/minimal.md",
					Tags:     nil,
				},
				Score: 0,
			},
			want: noteResult{
				ID:       7,
				FilePath: "notes/minimal.md",
				Tags:     nil,
			},
		},
		{
			name: "zero score filter entry",
			r: searchResultEntry{
				Note: note.Note{
					ID:       3,
					FilePath: "notes/filter.md",
					Title:    &title,
					Tags:     []string{},
				},
				Score: 0,
			},
			want: noteResult{
				ID:       3,
				FilePath: "notes/filter.md",
				Title:    "My Note",
				Tags:     []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := toNoteResult(&tt.r)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("toNoteResult() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestToTaskResult(t *testing.T) {
	t.Parallel()

	taskID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	yesterday := today.AddDate(0, 0, -1)
	threeDaysAgo := today.AddDate(0, 0, -3)
	tomorrow := today.AddDate(0, 0, 1)

	updatedAt := time.Date(2024, 1, 10, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		input task.PendingTaskDetail
		today time.Time
		want  taskResult
	}{
		{
			name: "task with future due date not overdue",
			input: task.PendingTaskDetail{
				ID:           taskID,
				Title:        "Write tests",
				Status:       "pending",
				Due:          &tomorrow,
				ProjectTitle: "Blog Backend",
				ProjectSlug:  "blog-backend",
				Energy:       "medium",
				Priority:     "high",
				MyDay:        true,
				UpdatedAt:    updatedAt,
			},
			today: today,
			want: taskResult{
				ID:           taskID.String(),
				Title:        "Write tests",
				Status:       "pending",
				Due:          tomorrow.Format(time.DateOnly),
				ProjectTitle: "Blog Backend",
				ProjectSlug:  "blog-backend",
				Energy:       "medium",
				Priority:     "high",
				IsRecurring:  false,
				MyDay:        true,
				UpdatedAt:    updatedAt.Format(time.RFC3339),
				OverdueDays:  0,
			},
		},
		{
			name: "task overdue by one day",
			input: task.PendingTaskDetail{
				ID:        taskID,
				Title:     "Overdue task",
				Status:    "pending",
				Due:       &yesterday,
				UpdatedAt: updatedAt,
			},
			today: today,
			want: taskResult{
				ID:          taskID.String(),
				Title:       "Overdue task",
				Status:      "pending",
				Due:         yesterday.Format(time.DateOnly),
				UpdatedAt:   updatedAt.Format(time.RFC3339),
				OverdueDays: 1,
			},
		},
		{
			name: "task overdue by three days",
			input: task.PendingTaskDetail{
				ID:        taskID,
				Title:     "Very overdue",
				Status:    "pending",
				Due:       &threeDaysAgo,
				UpdatedAt: updatedAt,
			},
			today: today,
			want: taskResult{
				ID:          taskID.String(),
				Title:       "Very overdue",
				Status:      "pending",
				Due:         threeDaysAgo.Format(time.DateOnly),
				UpdatedAt:   updatedAt.Format(time.RFC3339),
				OverdueDays: 3,
			},
		},
		{
			name: "task with no due date",
			input: task.PendingTaskDetail{
				ID:        taskID,
				Title:     "No due date",
				Status:    "pending",
				UpdatedAt: updatedAt,
			},
			today: today,
			want: taskResult{
				ID:        taskID.String(),
				Title:     "No due date",
				Status:    "pending",
				UpdatedAt: updatedAt.Format(time.RFC3339),
			},
		},
		{
			name: "recurring task",
			input: task.PendingTaskDetail{
				ID:            taskID,
				Title:         "Daily standup",
				Status:        "pending",
				RecurInterval: int32Ptr(1),
				UpdatedAt:     updatedAt,
			},
			today: today,
			want: taskResult{
				ID:          taskID.String(),
				Title:       "Daily standup",
				Status:      "pending",
				IsRecurring: true,
				UpdatedAt:   updatedAt.Format(time.RFC3339),
			},
		},
		{
			name: "non-recurring task has RecurInterval nil",
			input: task.PendingTaskDetail{
				ID:            taskID,
				Title:         "One-off",
				Status:        "pending",
				RecurInterval: nil,
				UpdatedAt:     updatedAt,
			},
			today: today,
			want: taskResult{
				ID:          taskID.String(),
				Title:       "One-off",
				Status:      "pending",
				IsRecurring: false,
				UpdatedAt:   updatedAt.Format(time.RFC3339),
			},
		},
		{
			name: "non-recurring task has RecurInterval zero",
			input: task.PendingTaskDetail{
				ID:            taskID,
				Title:         "Zero interval",
				Status:        "pending",
				RecurInterval: int32Ptr(0),
				UpdatedAt:     updatedAt,
			},
			today: today,
			want: taskResult{
				ID:          taskID.String(),
				Title:       "Zero interval",
				Status:      "pending",
				IsRecurring: false,
				UpdatedAt:   updatedAt.Format(time.RFC3339),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := toTaskResult(&tt.input, tt.today)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("toTaskResult() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
