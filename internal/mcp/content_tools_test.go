// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"context"
	"strings"
	"testing"
)

// Unit tests for the content lifecycle MCP tools (content_tools.go):
// create/update/submit/revert/archive/publish — DB-free dimensions only
// (input validation, the publish human-gate, error contracts). DB-backed
// transitions, audit, and idempotency live in integration_test.go.
//
// These unit tests pin the dimensions that fail BEFORE any DB call, so they
// run in the default `go test ./...` lane (no testcontainers):
//   - input validation  (content_id required / well-formed)
//   - actor / capability (human-only gate: requireExplicitHuman)
//   - error contract     (the exact rejection messages)
//
// Handler order is: id presence (publishContentTool) → uuid parse
// (publishContent) → requireExplicitHuman → DB. So id-validation rejections
// surface before the gate, and gate rejections surface before any DB touch —
// which is why a nil-store newTestServer() is sufficient here. DB side effects,
// audit, idempotency, and the success path are in
// integration_test.go (//go:build integration).

// invokePublish calls publish_content via its flat tool entrypoint with an
// optional explicit `as` identity. as=="" simulates a request that omitted
// `as` (falls through to the server default — must be refused by the
// human-only gate).
func invokePublish(t *testing.T, s *Server, as, contentID string) error {
	t.Helper()
	ctx := t.Context()
	if as != "" {
		ctx = context.WithValue(ctx, callerKey{}, as)
	}
	_, _, err := s.publishContentTool(ctx, nil, PublishContentInput{ContentID: contentID})
	return err
}

func TestPublishContent_InputAndGate(t *testing.T) {
	// A syntactically valid UUID that does not need to exist: every case here
	// is rejected before the DB lookup, so the row is never read.
	const validID = "11111111-1111-1111-1111-111111111111"

	tests := []struct {
		name       string
		as         string // "" = no explicit `as` (server default)
		contentID  string
		wantErrSub string
		dimension  string
	}{
		{
			name:       "missing content_id",
			as:         "human",
			contentID:  "",
			wantErrSub: "content_id is required",
			dimension:  "input validation",
		},
		{
			name:       "malformed content_id",
			as:         "human",
			contentID:  "not-a-uuid",
			wantErrSub: "invalid content_id",
			dimension:  "input validation",
		},
		{
			name:       "default caller refused (no explicit as)",
			as:         "",
			contentID:  validID,
			wantErrSub: "refusing without explicit `as`",
			dimension:  "actor/capability + error contract",
		},
		{
			name:       "agent caller refused (human-only)",
			as:         "hq",
			contentID:  validID,
			wantErrSub: "human-only",
			dimension:  "actor/capability + error contract",
		},
		{
			name:       "unregistered caller refused",
			as:         "ghost-agent",
			contentID:  validID,
			wantErrSub: "is not registered",
			dimension:  "actor/capability + error contract",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer() // nil pool — these paths never reach the DB
			err := invokePublish(t, s, tt.as, tt.contentID)
			if err == nil {
				t.Fatalf("publish_content(as=%q, id=%q) [%s] = nil error, want error containing %q",
					tt.as, tt.contentID, tt.dimension, tt.wantErrSub)
			}
			if !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Errorf("publish_content(as=%q, id=%q) error = %q, want substring %q",
					tt.as, tt.contentID, err.Error(), tt.wantErrSub)
			}
		})
	}
}

// TestPublishContent_GatePrecedesDB documents the ordering contract: the
// human-only gate refuses a non-human caller WITHOUT opening a transaction.
// newTestServer has a nil pool, so if the gate did not short-circuit, the
// handler would panic/error on s.pool — proving the gate runs first.
func TestPublishContent_GatePrecedesDB(t *testing.T) {
	s := newTestServer()
	const validID = "22222222-2222-2222-2222-222222222222"
	err := invokePublish(t, s, "hq", validID)
	if err == nil || !strings.Contains(err.Error(), "human-only") {
		t.Fatalf("publish_content(as=hq) = %v, want human-only rejection before any DB access", err)
	}
}

// Track 1E — content lifecycle contract (DB-free dimensions).
//
// These unit tests pin the input-validation dimension that fails before any DB
// access, so they run in the default `go test ./...` lane (no testcontainers).
// DB-backed transitions, audit, and idempotency live in
// integration_test.go (//go:build integration).
//
// The whole content authoring lifecycle — create/update plus the
// submit/revert/archive transitions — is author-allowlisted (content-studio,
// learning-studio, + human implicit); publish_content is human-gated (covered
// separately). The validation tests below run as newTestServer()'s default
// caller ("human"), which clears the author gate, so they exercise the
// validation/error contract rather than the gate. The gate itself is pinned by
// TestContentLifecycle_AuthorGatePrecedesDB. strPtr is the shared helper from
// handler_test.go.

func TestContentLifecycle_CreateValidation(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		ctype      string
		wantErrSub string
	}{
		{name: "missing title", title: "", ctype: "article", wantErrSub: "title is required"},
		{name: "missing content_type", title: "T", ctype: "", wantErrSub: "content_type is required"},
		{name: "invalid content_type", title: "T", ctype: "bookmark", wantErrSub: "invalid content_type"},
		{name: "note content_type rejected", title: "T", ctype: "note", wantErrSub: "no longer valid"},
		// GAP-C: a non-ASCII / punctuated title with no explicit slug derives
		// a non-conforming slug ("[test]-標題"); the handler must return a
		// caller-facing message, not leak the PG chk_content_slug_format error.
		{name: "non-ascii title yields invalid derived slug", title: "[TEST] 標題", ctype: "article", wantErrSub: "must be lowercase kebab-case"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer()
			_, _, err := s.createContentTool(t.Context(), nil, CreateContentInput{
				Title:       tt.title,
				ContentType: tt.ctype,
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Fatalf("createContentTool(title=%q,type=%q) err = %v, want substring %q",
					tt.title, tt.ctype, err, tt.wantErrSub)
			}
		})
	}
}

func TestContentLifecycle_UpdateValidation(t *testing.T) {
	const validID = "11111111-1111-1111-1111-111111111111"
	tests := []struct {
		name       string
		input      UpdateContentInput
		wantErrSub string
	}{
		{name: "missing id", input: UpdateContentInput{}, wantErrSub: "content_id is required"},
		{name: "malformed id", input: UpdateContentInput{ContentID: "not-a-uuid"}, wantErrSub: "invalid content_id"},
		// update_content is fields-only: ANY status (valid or invalid value) is
		// rejected before the DB; status transitions belong to dedicated tools.
		{name: "status change rejected (valid value)", input: UpdateContentInput{ContentID: validID, Status: strPtr("review")}, wantErrSub: "does not change status"},
		{name: "status change rejected (invalid value)", input: UpdateContentInput{ContentID: validID, Status: strPtr("publishedd")}, wantErrSub: "does not change status"},
		{name: "invalid content_type", input: UpdateContentInput{ContentID: validID, ContentType: strPtr("blog")}, wantErrSub: "invalid content_type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer()
			_, _, err := s.updateContentTool(t.Context(), nil, tt.input)
			if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Fatalf("updateContentTool(%+v) err = %v, want substring %q", tt.input, err, tt.wantErrSub)
			}
		})
	}
}

// TestContentLifecycle_AuthorGatePrecedesDB pins the author allowlist across
// the whole authoring lifecycle — create, update, and the submit/revert/archive
// transitions: blocked agents (hq, research-lab) are refused before any DB
// access, and an allowed agent (content-studio / learning-studio) clears the
// gate — proven by reaching field validation rather than the allowlist
// rejection. newTestServer() has a nil pool, so a caller that cleared the gate
// AND passed validation would panic on the tx; every case here stops before it.
func TestContentLifecycle_AuthorGatePrecedesDB(t *testing.T) {
	// invoke dispatches to a lifecycle tool with empty input, so an allowed
	// caller stops at the first field check (create → title; the rest →
	// content_id) and a blocked caller stops at the gate.
	invoke := func(t *testing.T, s *Server, tool string, ctx context.Context) error {
		t.Helper()
		switch tool {
		case "create":
			_, _, err := s.createContentTool(ctx, nil, CreateContentInput{})
			return err
		case "update":
			_, _, err := s.updateContentTool(ctx, nil, UpdateContentInput{})
			return err
		case "submit":
			_, _, err := s.submitContentForReviewTool(ctx, nil, SubmitContentForReviewInput{})
			return err
		case "revert":
			_, _, err := s.revertContentToDraftTool(ctx, nil, RevertContentToDraftInput{})
			return err
		case "archive":
			_, _, err := s.archiveContentTool(ctx, nil, ArchiveContentInput{})
			return err
		default:
			t.Fatalf("unknown tool %q", tool)
			return nil
		}
	}

	allowedErr := func(tool string) string {
		if tool == "create" {
			return "title is required"
		}
		return "content_id is required"
	}

	tools := []string{"create", "update", "submit", "revert", "archive"}
	for _, tool := range tools {
		t.Run(tool+" rejects hq", func(t *testing.T) {
			s := newTestServer() // nil pool — gate stops the call before the tx
			ctx := context.WithValue(t.Context(), callerKey{}, "hq")
			if err := invoke(t, s, tool, ctx); err == nil || !strings.Contains(err.Error(), "author allowlist") {
				t.Fatalf("%s as=hq err = %v, want author allowlist rejection", tool, err)
			}
		})
		t.Run(tool+" rejects research-lab", func(t *testing.T) {
			s := newTestServer()
			ctx := context.WithValue(t.Context(), callerKey{}, "research-lab")
			if err := invoke(t, s, tool, ctx); err == nil || !strings.Contains(err.Error(), "author allowlist") {
				t.Fatalf("%s as=research-lab err = %v, want author allowlist rejection", tool, err)
			}
		})
		// Allowed authors clear the gate and reach field validation instead of
		// the allowlist rejection.
		for _, as := range []string{"content-studio", "learning-studio"} {
			t.Run(tool+" allows "+as, func(t *testing.T) {
				s := newTestServer()
				ctx := context.WithValue(t.Context(), callerKey{}, as)
				if err := invoke(t, s, tool, ctx); err == nil || !strings.Contains(err.Error(), allowedErr(tool)) {
					t.Fatalf("%s as=%s err = %v, want substring %q", tool, as, err, allowedErr(tool))
				}
			})
		}
	}
}

// TestContentLifecycle_TransitionToolsValidation covers the DB-free input
// validation for the three transition wrappers (submit/revert/archive): an
// empty content_id is rejected by the tool, and a malformed UUID is rejected
// inside transitionContentStatus — both before any DB access.
func TestContentLifecycle_TransitionToolsValidation(t *testing.T) {
	// invoke calls the named tool with the given content_id and returns its error.
	invoke := func(s *Server, tool, id string) error {
		switch tool {
		case "submit":
			_, _, err := s.submitContentForReviewTool(t.Context(), nil, SubmitContentForReviewInput{ContentID: id})
			return err
		case "revert":
			_, _, err := s.revertContentToDraftTool(t.Context(), nil, RevertContentToDraftInput{ContentID: id})
			return err
		default: // archive
			_, _, err := s.archiveContentTool(t.Context(), nil, ArchiveContentInput{ContentID: id})
			return err
		}
	}
	tools := []string{"submit", "revert", "archive"}
	cases := []struct {
		name       string
		id         string
		wantErrSub string
	}{
		{name: "empty id", id: "", wantErrSub: "content_id is required"},
		{name: "malformed id", id: "not-a-uuid", wantErrSub: "invalid content_id"},
	}
	for _, tool := range tools {
		for _, c := range cases {
			t.Run(tool+"/"+c.name, func(t *testing.T) {
				s := newTestServer() // nil pool — both paths fail before the DB
				if err := invoke(s, tool, c.id); err == nil || !strings.Contains(err.Error(), c.wantErrSub) {
					t.Fatalf("%s(id=%q) err = %v, want substring %q", tool, c.id, err, c.wantErrSub)
				}
			})
		}
	}
}
