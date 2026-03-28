package mcpserver

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/task"
)

// --- validEnergy ---

func TestValidEnergy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "empty string is valid (optional field)", input: "", want: true},
		{name: "High is valid", input: "High", want: true},
		{name: "Low is valid", input: "Low", want: true},
		{name: "lowercase high is invalid", input: "high", want: false},
		{name: "lowercase low is invalid", input: "low", want: false},
		{name: "mixed case is invalid", input: "HIGH", want: false},
		{name: "unknown value is invalid", input: "Medium", want: false},
		{name: "whitespace is invalid", input: " ", want: false},
		{name: "High with trailing space is invalid", input: "High ", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := validEnergy(tt.input)
			if got != tt.want {
				t.Errorf("validEnergy(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func FuzzValidEnergy(f *testing.F) {
	f.Add("")
	f.Add("High")
	f.Add("Low")
	f.Add("high")
	f.Add("MEDIUM")
	f.Add("🔋")
	f.Fuzz(func(t *testing.T, input string) {
		_ = validEnergy(input) // must not panic
	})
}

// --- mapInputTaskStatus ---

func TestMapInputTaskStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  task.Status
	}{
		{name: "To Do", input: "To Do", want: task.StatusTodo},
		{name: "todo (lowercase alias)", input: "todo", want: task.StatusTodo},
		{name: "Doing", input: "Doing", want: task.StatusInProgress},
		{name: "In Progress", input: "In Progress", want: task.StatusInProgress},
		{name: "in-progress (kebab alias)", input: "in-progress", want: task.StatusInProgress},
		{name: "Done", input: "Done", want: task.StatusDone},
		{name: "done (lowercase alias)", input: "done", want: task.StatusDone},
		{name: "unknown defaults to todo", input: "Backlog", want: task.StatusTodo},
		{name: "empty string defaults to todo", input: "", want: task.StatusTodo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mapInputTaskStatus(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mapInputTaskStatus(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

// --- mapInputProjectStatus ---

func TestMapInputProjectStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  project.Status
	}{
		{name: "Planned", input: "Planned", want: project.StatusPlanned},
		{name: "planned (lowercase)", input: "planned", want: project.StatusPlanned},
		{name: "Doing", input: "Doing", want: project.StatusInProgress},
		{name: "In Progress", input: "In Progress", want: project.StatusInProgress},
		{name: "in-progress (kebab)", input: "in-progress", want: project.StatusInProgress},
		{name: "On Hold", input: "On Hold", want: project.StatusOnHold},
		{name: "on-hold (kebab)", input: "on-hold", want: project.StatusOnHold},
		{name: "Ongoing", input: "Ongoing", want: project.StatusMaintained},
		{name: "maintained (alias)", input: "maintained", want: project.StatusMaintained},
		{name: "Done", input: "Done", want: project.StatusCompleted},
		{name: "Completed", input: "Completed", want: project.StatusCompleted},
		{name: "completed (lowercase)", input: "completed", want: project.StatusCompleted},
		{name: "Archived", input: "Archived", want: project.StatusArchived},
		{name: "archived (lowercase)", input: "archived", want: project.StatusArchived},
		{name: "unknown defaults to in-progress", input: "Unknown", want: project.StatusInProgress},
		{name: "empty string defaults to in-progress", input: "", want: project.StatusInProgress},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mapInputProjectStatus(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mapInputProjectStatus(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

// --- mapInputGoalStatus ---

func TestMapInputGoalStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  goal.Status
	}{
		{name: "Dream", input: "Dream", want: goal.StatusNotStarted},
		{name: "Not Started", input: "Not Started", want: goal.StatusNotStarted},
		{name: "not-started (kebab)", input: "not-started", want: goal.StatusNotStarted},
		{name: "Active", input: "Active", want: goal.StatusInProgress},
		{name: "In Progress", input: "In Progress", want: goal.StatusInProgress},
		{name: "in-progress (kebab)", input: "in-progress", want: goal.StatusInProgress},
		{name: "Achieved", input: "Achieved", want: goal.StatusDone},
		{name: "Done", input: "Done", want: goal.StatusDone},
		{name: "done (lowercase)", input: "done", want: goal.StatusDone},
		{name: "Abandoned", input: "Abandoned", want: goal.StatusAbandoned},
		{name: "abandoned (lowercase)", input: "abandoned", want: goal.StatusAbandoned},
		{name: "unknown defaults to not-started", input: "Paused", want: goal.StatusNotStarted},
		{name: "empty string defaults to not-started", input: "", want: goal.StatusNotStarted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mapInputGoalStatus(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mapInputGoalStatus(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

// --- validateSessionNoteInput ---

func TestValidateSessionNoteInput(t *testing.T) {
	t.Parallel()

	validPlanMeta := map[string]any{
		"reasoning":          "clear the backlog",
		"committed_task_ids": []string{"abc", "def"},
	}
	validReflectionMeta := map[string]any{} // reflection has no required metadata
	validMetricsMeta := map[string]any{
		"tasks_planned":   3,
		"tasks_completed": 2,
		"adjustments":     "none",
	}
	validInsightMeta := map[string]any{
		"hypothesis":             "parallel tests are faster",
		"invalidation_condition": "CI p50 does not improve",
	}

	tests := []struct {
		name    string
		input   SaveSessionNoteInput
		wantErr bool
		errMsg  string
	}{
		// Happy paths
		{
			name: "valid plan note",
			input: SaveSessionNoteInput{
				NoteType: "plan",
				Content:  "Today I will focus on testing.",
				Source:   "claude",
				Metadata: validPlanMeta,
			},
			wantErr: false,
		},
		{
			name: "valid reflection note without metadata",
			input: SaveSessionNoteInput{
				NoteType: "reflection",
				Content:  "Good session, shipped 3 features.",
				Source:   "claude-code",
				Metadata: validReflectionMeta,
			},
			wantErr: false,
		},
		{
			name: "valid context note with no metadata",
			input: SaveSessionNoteInput{
				NoteType: "context",
				Content:  "Continuing from yesterday.",
				Source:   "manual",
			},
			wantErr: false,
		},
		{
			name: "valid metrics note",
			input: SaveSessionNoteInput{
				NoteType: "metrics",
				Content:  "3 planned, 2 done.",
				Source:   "claude",
				Metadata: validMetricsMeta,
			},
			wantErr: false,
		},
		{
			name: "valid insight note",
			input: SaveSessionNoteInput{
				NoteType: "insight",
				Content:  "Parallel tests improve CI speed.",
				Source:   "claude",
				Metadata: validInsightMeta,
			},
			wantErr: false,
		},
		// Missing required top-level fields
		{
			name: "missing note_type",
			input: SaveSessionNoteInput{
				Content: "some content",
				Source:  "claude",
			},
			wantErr: true,
			errMsg:  "note_type is required",
		},
		{
			name: "missing content",
			input: SaveSessionNoteInput{
				NoteType: "plan",
				Source:   "claude",
				Metadata: validPlanMeta,
			},
			wantErr: true,
			errMsg:  "content is required",
		},
		{
			name: "missing source",
			input: SaveSessionNoteInput{
				NoteType: "plan",
				Content:  "some content",
				Metadata: validPlanMeta,
			},
			wantErr: true,
			errMsg:  "source is required",
		},
		// Invalid enum values
		{
			name: "invalid note_type",
			input: SaveSessionNoteInput{
				NoteType: "journal",
				Content:  "some content",
				Source:   "claude",
			},
			wantErr: true,
			errMsg:  `invalid note_type "journal"`,
		},
		{
			name: "invalid source",
			input: SaveSessionNoteInput{
				NoteType: "reflection",
				Content:  "some content",
				Source:   "gpt",
			},
			wantErr: true,
			errMsg:  `invalid source "gpt"`,
		},
		// Missing required metadata for typed notes
		{
			name: "plan note missing reasoning",
			input: SaveSessionNoteInput{
				NoteType: "plan",
				Content:  "Today's plan.",
				Source:   "claude",
				Metadata: map[string]any{
					"committed_task_ids": []string{"abc"},
				},
			},
			wantErr: true,
			errMsg:  "plan metadata requires 'reasoning' field",
		},
		{
			name: "plan note missing committed tasks",
			input: SaveSessionNoteInput{
				NoteType: "plan",
				Content:  "Today's plan.",
				Source:   "claude",
				Metadata: map[string]any{
					"reasoning": "clear the backlog",
				},
			},
			wantErr: true,
			errMsg:  "plan metadata requires 'committed_task_ids' or 'committed_items'",
		},
		{
			name: "metrics note missing tasks_planned",
			input: SaveSessionNoteInput{
				NoteType: "metrics",
				Content:  "Metrics.",
				Source:   "claude",
				Metadata: map[string]any{
					"tasks_completed": 2,
					"adjustments":     "none",
				},
			},
			wantErr: true,
			errMsg:  "metrics metadata requires 'tasks_planned' field",
		},
		{
			name: "insight note missing invalidation_condition",
			input: SaveSessionNoteInput{
				NoteType: "insight",
				Content:  "An insight.",
				Source:   "claude",
				Metadata: map[string]any{
					"hypothesis": "parallel is faster",
				},
			},
			wantErr: true,
			errMsg:  "insight metadata requires 'invalidation_condition' field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateSessionNoteInput(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("validateSessionNoteInput() expected error containing %q, got nil", tt.errMsg)
				}
				if tt.errMsg != "" {
					errStr := err.Error()
					if errStr == "" || !strings.Contains(errStr, tt.errMsg) {
						t.Errorf("validateSessionNoteInput() error = %q, want to contain %q", errStr, tt.errMsg)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("validateSessionNoteInput() unexpected error: %v", err)
			}
		})
	}
}

func FuzzValidateSessionNoteInput(f *testing.F) {
	f.Add("plan", "some content", "claude")
	f.Add("reflection", "some content", "claude-code")
	f.Add("insight", "", "manual")
	f.Add("", "", "")
	f.Add("unknown", "x", "y")
	f.Fuzz(func(t *testing.T, noteType, content, source string) {
		input := SaveSessionNoteInput{
			NoteType: noteType,
			Content:  content,
			Source:   source,
		}
		_ = validateSessionNoteInput(input) // must not panic
	})
}

// --- validateSessionNoteMetadata ---

func TestValidateSessionNoteMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		noteType string
		meta     map[string]any
		wantErr  bool
		errMsg   string
	}{
		// insight: valid
		{
			name:     "insight with both required fields",
			noteType: "insight",
			meta: map[string]any{
				"hypothesis":             "caching reduces latency",
				"invalidation_condition": "p99 does not improve",
			},
			wantErr: false,
		},
		// insight: missing fields
		{
			name:     "insight missing hypothesis",
			noteType: "insight",
			meta: map[string]any{
				"invalidation_condition": "p99 does not improve",
			},
			wantErr: true,
			errMsg:  "insight metadata requires 'hypothesis' field",
		},
		{
			name:     "insight missing invalidation_condition",
			noteType: "insight",
			meta: map[string]any{
				"hypothesis": "caching reduces latency",
			},
			wantErr: true,
			errMsg:  "insight metadata requires 'invalidation_condition' field",
		},
		{
			name:     "insight with nil metadata",
			noteType: "insight",
			meta:     nil,
			wantErr:  true,
			errMsg:   "insight metadata requires 'hypothesis' field",
		},
		// plan: valid with committed_task_ids
		{
			name:     "plan with committed_task_ids",
			noteType: "plan",
			meta: map[string]any{
				"reasoning":          "focus on reliability",
				"committed_task_ids": []string{"task-1"},
			},
			wantErr: false,
		},
		// plan: valid with committed_items
		{
			name:     "plan with committed_items instead",
			noteType: "plan",
			meta: map[string]any{
				"reasoning":       "focus on reliability",
				"committed_items": "write tests",
			},
			wantErr: false,
		},
		// plan: missing reasoning
		{
			name:     "plan missing reasoning",
			noteType: "plan",
			meta: map[string]any{
				"committed_task_ids": []string{"task-1"},
			},
			wantErr: true,
			errMsg:  "plan metadata requires 'reasoning' field",
		},
		// plan: missing committed tasks (neither key)
		{
			name:     "plan missing committed_task_ids and committed_items",
			noteType: "plan",
			meta: map[string]any{
				"reasoning": "focus on reliability",
			},
			wantErr: true,
			errMsg:  "plan metadata requires 'committed_task_ids' or 'committed_items'",
		},
		// metrics: valid
		{
			name:     "metrics with all required fields",
			noteType: "metrics",
			meta: map[string]any{
				"tasks_planned":   5,
				"tasks_completed": 4,
				"adjustments":     "deferred one task",
			},
			wantErr: false,
		},
		// metrics: missing individual fields
		{
			name:     "metrics missing tasks_planned",
			noteType: "metrics",
			meta: map[string]any{
				"tasks_completed": 4,
				"adjustments":     "none",
			},
			wantErr: true,
			errMsg:  "metrics metadata requires 'tasks_planned' field",
		},
		{
			name:     "metrics missing tasks_completed",
			noteType: "metrics",
			meta: map[string]any{
				"tasks_planned": 5,
				"adjustments":   "none",
			},
			wantErr: true,
			errMsg:  "metrics metadata requires 'tasks_completed' field",
		},
		{
			name:     "metrics missing adjustments",
			noteType: "metrics",
			meta: map[string]any{
				"tasks_planned":   5,
				"tasks_completed": 4,
			},
			wantErr: true,
			errMsg:  "metrics metadata requires 'adjustments' field",
		},
		// context and reflection: no metadata requirements
		{
			name:     "context with nil metadata is valid",
			noteType: "context",
			meta:     nil,
			wantErr:  false,
		},
		{
			name:     "reflection with empty metadata is valid",
			noteType: "reflection",
			meta:     map[string]any{},
			wantErr:  false,
		},
		// unknown note type: no metadata requirements enforced
		{
			name:     "unknown note type with nil metadata is valid",
			noteType: "unknown",
			meta:     nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateSessionNoteMetadata(tt.noteType, tt.meta)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("validateSessionNoteMetadata(%q) expected error containing %q, got nil", tt.noteType, tt.errMsg)
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateSessionNoteMetadata(%q) error = %q, want to contain %q", tt.noteType, err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateSessionNoteMetadata(%q) unexpected error: %v", tt.noteType, err)
			}
		})
	}
}

// --- buildNotionTaskProps ---

func TestBuildNotionTaskProps(t *testing.T) {
	t.Parallel()

	boolPtr := func(v bool) *bool { return &v }

	tests := []struct {
		name  string
		input *UpdateTaskInput
		want  map[string]any
	}{
		{
			name:  "nil-pointer fields produce empty map",
			input: &UpdateTaskInput{},
			want:  map[string]any{},
		},
		{
			name: "new title is mapped",
			input: &UpdateTaskInput{
				NewTitle: strPtr("Renamed Task"),
			},
			want: map[string]any{
				"Task Name": map[string]any{
					"title": []map[string]any{
						{"text": map[string]string{"content": "Renamed Task"}},
					},
				},
			},
		},
		{
			name: "status is mapped",
			input: &UpdateTaskInput{
				Status: strPtr("Doing"),
			},
			want: map[string]any{
				"Status": map[string]any{
					"status": map[string]string{"name": "Doing"},
				},
			},
		},
		{
			name: "due date is mapped",
			input: &UpdateTaskInput{
				Due: strPtr("2026-04-01"),
			},
			want: map[string]any{
				"Due": map[string]any{
					"date": map[string]string{"start": "2026-04-01"},
				},
			},
		},
		{
			name: "empty due date clears the field",
			input: &UpdateTaskInput{
				Due: strPtr(""),
			},
			want: map[string]any{
				"Due": map[string]any{"date": nil},
			},
		},
		{
			name: "priority is mapped",
			input: &UpdateTaskInput{
				Priority: strPtr("High"),
			},
			want: map[string]any{
				"Priority": map[string]any{
					"status": map[string]string{"name": "High"},
				},
			},
		},
		{
			name: "empty priority clears the field",
			input: &UpdateTaskInput{
				Priority: strPtr(""),
			},
			want: map[string]any{
				"Priority": map[string]any{"status": nil},
			},
		},
		{
			name: "energy High is mapped",
			input: &UpdateTaskInput{
				Energy: strPtr("High"),
			},
			want: map[string]any{
				"Energy": map[string]any{
					"select": map[string]string{"name": "High"},
				},
			},
		},
		{
			name: "empty energy clears the field",
			input: &UpdateTaskInput{
				Energy: strPtr(""),
			},
			want: map[string]any{
				"Energy": map[string]any{"select": nil},
			},
		},
		{
			name: "my_day true is mapped",
			input: &UpdateTaskInput{
				MyDay: boolPtr(true),
			},
			want: map[string]any{
				"My Day": map[string]any{"checkbox": true},
			},
		},
		{
			name: "my_day false is mapped",
			input: &UpdateTaskInput{
				MyDay: boolPtr(false),
			},
			want: map[string]any{
				"My Day": map[string]any{"checkbox": false},
			},
		},
		{
			name: "full input with all fields set",
			input: &UpdateTaskInput{
				NewTitle: strPtr("Full Update"),
				Status:   strPtr("Done"),
				Due:      strPtr("2026-05-15"),
				Priority: strPtr("Low"),
				Energy:   strPtr("Low"),
				MyDay:    boolPtr(true),
			},
			want: map[string]any{
				"Task Name": map[string]any{
					"title": []map[string]any{
						{"text": map[string]string{"content": "Full Update"}},
					},
				},
				"Status": map[string]any{
					"status": map[string]string{"name": "Done"},
				},
				"Due": map[string]any{
					"date": map[string]string{"start": "2026-05-15"},
				},
				"Priority": map[string]any{
					"status": map[string]string{"name": "Low"},
				},
				"Energy": map[string]any{
					"select": map[string]string{"name": "Low"},
				},
				"My Day": map[string]any{"checkbox": true},
			},
		},
		{
			name: "special characters in title",
			input: &UpdateTaskInput{
				NewTitle: strPtr(`Fix "race condition" & panic < > edge`),
			},
			want: map[string]any{
				"Task Name": map[string]any{
					"title": []map[string]any{
						{"text": map[string]string{"content": `Fix "race condition" & panic < > edge`}},
					},
				},
			},
		},
		{
			name: "project field is not included (handled by caller)",
			input: &UpdateTaskInput{
				Project: strPtr("blog-backend"),
			},
			want: map[string]any{},
		},
		{
			name: "notes field is not included (handled by local DB only)",
			input: &UpdateTaskInput{
				Notes: strPtr("some notes"),
			},
			want: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildNotionTaskProps(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("buildNotionTaskProps() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
