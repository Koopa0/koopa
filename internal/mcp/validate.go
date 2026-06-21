// Copyright 2026 Koopa. All rights reserved.

// validate.go holds shared MCP input validators used across KEPT tools
// (capture_inbox, manage_plan, content, learning). They enforce
// schema CHECK-constraint vocabularies client-side so handlers return a
// specific error instead of a generic Postgres CheckViolation.

package mcp

// isValidEnergy mirrors the todos.energy CHECK in 001_initial.up.sql.
// Used by capture_inbox.
func isValidEnergy(e string) bool {
	switch e {
	case "high", "medium", "low":
		return true
	default:
		return false
	}
}

// isValidPlanEntryStatus mirrors the values manage_plan(action=update_entry)
// is allowed to write to learning_plan_entries.status.
func isValidPlanEntryStatus(s string) bool {
	switch s {
	case "completed", "skipped", "substituted":
		return true
	default:
		return false
	}
}
