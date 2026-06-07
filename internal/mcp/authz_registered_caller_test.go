// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// authz_registered_caller_test.go is the behavioural confirmation for the
// "ungated mutating tool" hole: the write tools that carry no identity gate
// (capture_inbox, track_hypothesis, start_session, record_attempt,
// end_session, manage_plan, create_note, update_note, update_note_maturity)
// must refuse a caller that does not resolve to a known, registered author
// before any store write happens.
//
// The gate is requireRegisteredCaller (authz.go). It reuses the existing
// registry — the same one requireAuthor already consults — and refuses two
// callers:
//
//   - an `as` value naming no registry row (e.g. "not-a-registered-agent");
//   - the zero-privilege "unknown" sentinel, which is the server default
//     when a call omits `as` (cmd/mcp/config.go). "unknown" is registered
//     only so the audit-trigger actor FK resolves; it is not a known
//     author, so a knowledge-base / settings write attributed to it is
//     refused (decision: knowledge-base / settings writes require a known
//     author).
//
// This is the weakest identity gate in the package — registration only,
// no capability subdivision (that is a later pass). The tests run against
// the testcontainers pool; the "currently SUCCEEDS → after fix REJECTED"
// transition is the RED→GREEN signal.
package mcp

import (
	"testing"
)

// TestIntegration_MutatingTools_RejectUnregisteredCaller confirms create_note:
// a caller that names an agent absent from the registry is refused, and —
// critically — the gate fires BEFORE the store write, so no row is created.
func TestIntegration_MutatingTools_RejectUnregisteredCaller(t *testing.T) {
	const ghost = "not-a-registered-agent"

	// --- T2: create_note as unregistered ---
	t.Run("create_note", func(t *testing.T) {
		s := setupServer(t)
		_, _, err := callHandlerAs(t, ghost, s.createNote, CreateNoteInput{
			Slug:  "gate-test-note",
			Title: "Gate Test Note",
			Body:  "should never persist",
			Kind:  "musing",
		})
		if err == nil {
			t.Fatal("create_note as unregistered = nil error, want rejection")
		}
		if !contains(err.Error(), "not registered") {
			t.Errorf("create_note error = %q, want containing %q", err, "not registered")
		}
		var count int
		if qerr := testPool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM notes WHERE slug = $1`, "gate-test-note").Scan(&count); qerr != nil {
			t.Fatalf("counting notes: %v", qerr)
		}
		if count != 0 {
			t.Errorf("notes rows after rejected create = %d, want 0", count)
		}
	})
}

// TestIntegration_MutatingTools_RegisteredCallerStillWrites is T3: the gate
// must NOT regress legitimate writes. Real registered agents — picked per
// each tool's existing rules (notes/feeds carry no author allowlist, so any
// registered agent is admitted) — still succeed.
func TestIntegration_MutatingTools_RegisteredCallerStillWrites(t *testing.T) {
	t.Run("create_note as planner", func(t *testing.T) {
		s := setupServer(t)
		_, out, err := callHandlerAs(t, "planner", s.createNote, CreateNoteInput{
			Slug:  "registered-author-note",
			Title: "Registered Author Note",
			Body:  "persists",
			Kind:  "musing",
		})
		if err != nil {
			t.Fatalf("create_note as planner = %v, want success", err)
		}
		if out.Note == nil || out.Note.CreatedBy != "planner" {
			t.Fatalf("create_note as planner created_by = %+v, want planner", out.Note)
		}
	})
}
