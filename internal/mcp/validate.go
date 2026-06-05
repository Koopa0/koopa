// Copyright 2026 Koopa. All rights reserved.

// validate.go holds shared MCP input validators used across KEPT tools
// (capture_inbox, advance_work, manage_plan, content, goals). They enforce
// schema CHECK-constraint vocabularies client-side so handlers return a
// specific error instead of a generic Postgres CheckViolation.

package mcp

import (
	"fmt"
	"regexp"
)

// slugPattern mirrors every chk_*_slug_format CHECK constraint in
// migrations/001 (learning_domains, concepts, contents, tags, topics,
// observation_categories, ...). Validating client-side lets handlers
// return a specific error instead of a generic CheckViolation from PG.
//
// The canonical form is strictly aligned with the DB so a slug accepted
// here is always accepted by INSERT: it allows leading digits (e.g.
// "n2-grammar") and rejects trailing/consecutive hyphens.
//
// If a future migration changes the schema rule, update this regex in
// the same commit so client-side and server-side stay aligned.
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// validateSlug returns an error suitable for caller-facing messages
// when s does not match slugPattern. fieldName is the human-readable
// name to show ("concept slug", "content slug", "observation category").
// Returns nil for valid slugs. The wording is intentionally uniform so
// all slug rejections read the same regardless of which tool the caller used.
func validateSlug(fieldName, s string) error {
	if slugPattern.MatchString(s) {
		return nil
	}
	return fmt.Errorf("invalid %s %q: must be lowercase kebab-case (pattern: %s)", fieldName, s, slugPattern.String())
}

// isValidTaskPriority reports whether p matches the tasks.priority CHECK
// constraint vocabulary. Mirrors the enum in migrations/001_initial.up.sql.
func isValidTaskPriority(p string) bool {
	switch p {
	case "high", "medium", "low":
		return true
	default:
		return false
	}
}

// isValidEnergy mirrors the todos.energy CHECK in 001_initial.up.sql.
// Used by capture_inbox and advance_work(action=clarify).
func isValidEnergy(e string) bool {
	switch e {
	case "high", "medium", "low":
		return true
	default:
		return false
	}
}

// isValidContentStatus mirrors the contents.status CHECK.
func isValidContentStatus(s string) bool {
	switch s {
	case "draft", "review", "published", "archived":
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

// isValidPlanStatus mirrors the values manage_plan(action=update_plan) is
// allowed to write to learning_plans.status.
func isValidPlanStatus(s string) bool {
	switch s {
	case "active", "paused", "completed", "abandoned":
		return true
	default:
		return false
	}
}
