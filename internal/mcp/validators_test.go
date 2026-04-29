package mcp

import "testing"

// TestValidators is one table-driven test per enum-string validator.
// These exist so adding or renaming a CHECK-constraint enum value in
// migrations forces an explicit decision here, not a silent surface
// area where invalid values pass MCP and only get rejected at the DB.
func TestValidators(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fn   func(string) bool
		good []string
		bad  []string
	}{
		{
			name: "energy",
			fn:   isValidEnergy,
			good: []string{"high", "medium", "low"},
			bad:  []string{"", "HIGH", "urgent", "none", "light"},
		},
		{
			name: "task_priority",
			fn:   isValidTaskPriority,
			good: []string{"high", "medium", "low"},
			bad:  []string{"", "p0", "critical", "Medium"},
		},
		{
			name: "content_status",
			fn:   isValidContentStatus,
			good: []string{"draft", "review", "published", "archived"},
			bad:  []string{"", "DRAFT", "publish", "deleted"},
		},
		{
			name: "plan_entry_status",
			fn:   isValidPlanEntryStatus,
			good: []string{"completed", "skipped", "substituted"},
			bad:  []string{"", "active", "abandoned", "Completed"},
		},
		{
			name: "plan_status",
			fn:   isValidPlanStatus,
			good: []string{"active", "paused", "completed", "abandoned"},
			bad:  []string{"", "draft", "skipped", "Active"},
		},
		{
			name: "goal_status_filter",
			fn:   isValidGoalStatusFilter,
			good: []string{"all", "not_started", "in_progress", "done", "abandoned", "on_hold"},
			bad:  []string{"", "ALL", "active", "completed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, in := range tt.good {
				if !tt.fn(in) {
					t.Errorf("%s(%q) = false, want true", tt.name, in)
				}
			}
			for _, in := range tt.bad {
				if tt.fn(in) {
					t.Errorf("%s(%q) = true, want false", tt.name, in)
				}
			}
		})
	}
}
