// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestWeekdayBitsMatchesCanonicalSpec pins the MCP weekday→bit map to the
// documented recur_weekdays mask (Mon=bit0 .. Sun=bit6), matching the
// COMMENT ON COLUMN in migrations/001_initial.up.sql and the SQL ISODOW-1
// shift in RecurringTodoItemsDueToday. internal/todo carries a deliberate copy
// of this map (handler.go) with its own mirror test; the schema CHECK only
// range-checks 1..127, so a bit→weekday drift on either copy would otherwise go
// uncaught. If this fails, the MCP map and the admin map (or the documented
// spec) have diverged.
func TestWeekdayBitsMatchesCanonicalSpec(t *testing.T) {
	canonical := map[string]int16{
		"mon": 1, "tue": 2, "wed": 4, "thu": 8, "fri": 16, "sat": 32, "sun": 64,
	}
	if diff := cmp.Diff(canonical, weekdayBits); diff != "" {
		t.Errorf("mcp weekdayBits drifted from the documented Mon=1..Sun=64 mask (-want +got):\n%s", diff)
	}
}
