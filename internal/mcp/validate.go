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

// containsProseControlChars reports whether s contains a control character
// forbidden in multi-line free-text prose: every control char EXCEPT HT
// (0x09), LF (0x0A), and CR (0x0D). A content body is multi-line Markdown
// where line breaks and tabs are legitimate formatting, so propose_content
// validates the body with this instead of goal.ContainsControlChars (which
// rejects every C0 control and is reserved for single-line fields like title).
// Mirrors internal/reading and internal/song.
func containsProseControlChars(s string) bool {
	for _, r := range s {
		switch {
		case r == 0x09, r == 0x0a, r == 0x0d:
			continue
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			return true
		}
	}
	return false
}
