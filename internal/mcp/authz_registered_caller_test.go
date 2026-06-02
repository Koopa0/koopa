// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// authz_registered_caller_test.go is the behavioural confirmation for the
// "ungated mutating tool" hole: the eleven write tools that carry no
// identity gate (capture_inbox, write_agent_note, track_hypothesis,
// start_session, record_attempt, end_session, manage_plan, create_note,
// update_note, update_note_maturity, manage_feeds) must refuse a caller
// that does not resolve to a known, registered author before any store
// write happens.
//
// The gate is requireRegisteredCaller (authz.go). It reuses the existing
// registry — the same one requireAuthor / requireExplicitHuman /
// agent.Authorize already consult — and refuses two callers:
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

	"github.com/google/uuid"
)

// TestIntegration_MutatingTools_RejectUnregisteredCaller is T1 (manage_feeds
// add + remove) and T2 (write_agent_note + create_note): a caller that names
// an agent absent from the registry is refused, and — critically — the gate
// fires BEFORE the store write, so no row is created.
func TestIntegration_MutatingTools_RejectUnregisteredCaller(t *testing.T) {
	const ghost = "not-a-registered-agent"

	// --- T1: manage_feeds(add) as unregistered ---
	t.Run("manage_feeds add", func(t *testing.T) {
		s := setupServer(t)
		_, topicIDStr := seedFeedTopic(t, "gate-add-fixture", "Gate Add Fixture")

		feedURL := "https://example.com/gate-add-feed.xml"
		feedName := "Gate Add Feed"
		schedule := "hourly"

		_, _, err := callHandlerAs(t, ghost, s.manageFeeds, ManageFeedsInput{
			Action:   "add",
			URL:      &feedURL,
			Name:     &feedName,
			Schedule: &schedule,
			TopicIDs: []string{topicIDStr},
		})
		if err == nil {
			t.Fatal("manage_feeds(add) as unregistered = nil error, want rejection")
		}
		if !contains(err.Error(), "not registered") {
			t.Errorf("manage_feeds(add) error = %q, want containing %q", err, "not registered")
		}
		// The gate must precede the store write — no feed row may exist.
		var count int
		if qerr := testPool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM feeds WHERE url = $1`, feedURL).Scan(&count); qerr != nil {
			t.Fatalf("counting feeds: %v", qerr)
		}
		if count != 0 {
			t.Errorf("feeds rows after rejected add = %d, want 0 (gate must run before store)", count)
		}
	})

	// --- T1: manage_feeds(remove) as unregistered ---
	// Seed a real feed as the registered default first, then prove the
	// unregistered remove is refused on identity (not masked by not-found)
	// and the row survives.
	t.Run("manage_feeds remove", func(t *testing.T) {
		s := setupServer(t)
		_, topicIDStr := seedFeedTopic(t, "gate-rm-fixture", "Gate Rm Fixture")

		feedURL := "https://example.com/gate-rm-feed.xml"
		feedName := "Gate Rm Feed"
		schedule := "daily"

		// Registered default (learning-studio) — succeeds (also exercises T3).
		_, addOut, err := callHandler(t, s.manageFeeds, ManageFeedsInput{
			Action:   "add",
			URL:      &feedURL,
			Name:     &feedName,
			Schedule: &schedule,
			TopicIDs: []string{topicIDStr},
		})
		if err != nil {
			t.Fatalf("seed manage_feeds(add) as registered default: %v", err)
		}
		feedID := addOut.Feed.ID.String()

		_, _, err = callHandlerAs(t, ghost, s.manageFeeds, ManageFeedsInput{
			Action: "remove",
			FeedID: &feedID,
		})
		if err == nil {
			t.Fatal("manage_feeds(remove) as unregistered = nil error, want rejection")
		}
		if !contains(err.Error(), "not registered") {
			t.Errorf("manage_feeds(remove) error = %q, want containing %q", err, "not registered")
		}
		// The feed must survive the rejected remove.
		var count int
		if qerr := testPool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM feeds WHERE url = $1`, feedURL).Scan(&count); qerr != nil {
			t.Fatalf("counting feeds: %v", qerr)
		}
		if count != 1 {
			t.Errorf("feeds rows after rejected remove = %d, want 1 (gate must run before store)", count)
		}
	})

	// --- T2: write_agent_note as unregistered ---
	t.Run("write_agent_note", func(t *testing.T) {
		s := setupServer(t)
		_, _, err := callHandlerAs(t, ghost, s.writeAgentNote, WriteAgentNoteInput{
			Kind:    "context",
			Content: "gate test — should never persist",
		})
		if err == nil {
			t.Fatal("write_agent_note as unregistered = nil error, want rejection")
		}
		if !contains(err.Error(), "not registered") {
			t.Errorf("write_agent_note error = %q, want containing %q", err, "not registered")
		}
		var count int
		if qerr := testPool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM agent_notes WHERE content = $1`,
			"gate test — should never persist").Scan(&count); qerr != nil {
			t.Fatalf("counting agent_notes: %v", qerr)
		}
		if count != 0 {
			t.Errorf("agent_notes rows after rejected write = %d, want 0", count)
		}
	})

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
	t.Run("manage_feeds add as learning-studio", func(t *testing.T) {
		s := setupServer(t)
		_, topicIDStr := seedFeedTopic(t, "gate-ok-fixture", "Gate OK Fixture")
		feedURL := "https://example.com/gate-ok-feed.xml"
		feedName := "Gate OK Feed"
		schedule := "weekly"

		_, out, err := callHandlerAs(t, "learning-studio", s.manageFeeds, ManageFeedsInput{
			Action:   "add",
			URL:      &feedURL,
			Name:     &feedName,
			Schedule: &schedule,
			TopicIDs: []string{topicIDStr},
		})
		if err != nil {
			t.Fatalf("manage_feeds(add) as learning-studio = %v, want success", err)
		}
		if out.Feed == nil || out.Feed.ID.String() == "" {
			t.Fatal("manage_feeds(add) as learning-studio returned no feed")
		}
	})

	t.Run("write_agent_note as content-studio", func(t *testing.T) {
		s := setupServer(t)
		_, out, err := callHandlerAs(t, "content-studio", s.writeAgentNote, WriteAgentNoteInput{
			Kind:    "context",
			Content: "registered author note",
		})
		if err != nil {
			t.Fatalf("write_agent_note as content-studio = %v, want success", err)
		}
		if out.Entry.ID == uuid.Nil {
			t.Fatal("write_agent_note as content-studio returned empty entry id")
		}
	})

	t.Run("create_note as hq", func(t *testing.T) {
		s := setupServer(t)
		_, out, err := callHandlerAs(t, "hq", s.createNote, CreateNoteInput{
			Slug:  "registered-author-note",
			Title: "Registered Author Note",
			Body:  "persists",
			Kind:  "musing",
		})
		if err != nil {
			t.Fatalf("create_note as hq = %v, want success", err)
		}
		if out.Note == nil || out.Note.CreatedBy != "hq" {
			t.Fatalf("create_note as hq created_by = %+v, want hq", out.Note)
		}
	})
}

// TestIntegration_ManageFeeds_RejectsUnknownAuthor is T4: a write that does
// not name a known author is refused. Two shapes resolve to the
// zero-privilege "unknown" sentinel and both must be rejected:
//
//   - omitting `as` when the server default is the production default
//     "unknown" (the fail-closed default from cmd/mcp/config.go);
//   - passing `as: "unknown"` explicitly (a client mirroring the default).
//
// setupServer pins callerAgent="learning-studio", so the test overrides it
// to the production default "unknown" for the omit-`as` case (the field is
// package-private and this test is white-box).
func TestIntegration_ManageFeeds_RejectsUnknownAuthor(t *testing.T) {
	mkInput := func(url string) ManageFeedsInput {
		feedURL := url
		feedName := "Unknown Author Feed"
		schedule := "hourly"
		return ManageFeedsInput{
			Action:   "add",
			URL:      &feedURL,
			Name:     &feedName,
			Schedule: &schedule,
		}
	}

	t.Run("omit as resolves to unknown default", func(t *testing.T) {
		s := setupServer(t)
		s.callerAgent = "unknown" // mirror cmd/mcp/config.go production default
		url := "https://example.com/unknown-default-feed.xml"

		_, _, err := callHandler(t, s.manageFeeds, mkInput(url))
		if err == nil {
			t.Fatal("manage_feeds(add) with omitted `as` (default unknown) = nil error, want rejection")
		}
		var count int
		if qerr := testPool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM feeds WHERE url = $1`, url).Scan(&count); qerr != nil {
			t.Fatalf("counting feeds: %v", qerr)
		}
		if count != 0 {
			t.Errorf("feeds rows after rejected add = %d, want 0", count)
		}
	})

	t.Run("explicit as=unknown", func(t *testing.T) {
		s := setupServer(t)
		url := "https://example.com/unknown-explicit-feed.xml"

		_, _, err := callHandlerAs(t, "unknown", s.manageFeeds, mkInput(url))
		if err == nil {
			t.Fatal("manage_feeds(add) with as=unknown = nil error, want rejection")
		}
		var count int
		if qerr := testPool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM feeds WHERE url = $1`, url).Scan(&count); qerr != nil {
			t.Fatalf("counting feeds: %v", qerr)
		}
		if count != 0 {
			t.Errorf("feeds rows after rejected add = %d, want 0", count)
		}
	})
}
