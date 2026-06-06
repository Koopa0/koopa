// Copyright 2026 Koopa. All rights reserved.

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
