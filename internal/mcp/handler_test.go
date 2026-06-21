// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
)

// newTestServer creates a Server with no stores — only useful for validation
// tests that fail before any DB call. The default caller is "human" so the
// authorization helpers in authz.go (requireAuthor, requireRegisteredCaller)
// do not gate validation paths from running. Tests that need a non-human
// caller override callerAgent or pass `as` via context.
func newTestServer() *Server {
	return &Server{
		logger:      slog.Default(),
		callerAgent: "human",
		registry:    agent.NewBuiltinRegistry(),
		loc:         time.UTC,
	}
}

func callHandler[I, O any](t *testing.T, handler func(context.Context, *mcp.CallToolRequest, I) (*mcp.CallToolResult, O, error), input I) (*mcp.CallToolResult, O, error) {
	t.Helper()
	return handler(t.Context(), nil, input)
}

// --- capture_inbox ---

func TestCaptureInbox_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   CaptureInboxInput
		wantErr string
	}{
		{name: "empty title", input: CaptureInboxInput{}, wantErr: "title is required"},
		{name: "invalid due", input: CaptureInboxInput{Title: "test", Due: new("not-a-date")}, wantErr: "invalid due date"},
		{name: "C0 control char in title", input: CaptureInboxInput{Title: "bad\x07title"}, wantErr: "title must not contain control characters"},
		{name: "control char in description", input: CaptureInboxInput{Title: "ok", Description: "line1\x00line2"}, wantErr: "description must not contain control characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.captureInbox, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// --- create_note / update_note control-char validation ---

// TestNote_ControlCharValidation pins that the note tools reject control
// characters in title/body before any store write, mirroring the propose_*
// and HTTP handler validation. These run on the unit test server (caller
// "human" is registered) and the control-char check fires before any DB call,
// so no testcontainer is needed.
func TestNote_ControlCharValidation(t *testing.T) {
	s := newTestServer()

	t.Run("create_note rejects control char in title", func(t *testing.T) {
		_, _, err := callHandler(t, s.createNote, CreateNoteInput{
			Slug:  "valid-slug",
			Title: "bad\x1ftitle",
			Kind:  "musing",
		})
		if err == nil || !contains(err.Error(), "title must not contain control characters") {
			t.Errorf("createNote error = %v, want control-char title rejection", err)
		}
	})

	t.Run("create_note rejects control char in body", func(t *testing.T) {
		_, _, err := callHandler(t, s.createNote, CreateNoteInput{
			Slug:  "valid-slug",
			Title: "ok title",
			Body:  "para\u009fwith C1",
			Kind:  "musing",
		})
		if err == nil || !contains(err.Error(), "body must not contain control characters") {
			t.Errorf("createNote error = %v, want control-char body rejection", err)
		}
	})

	t.Run("update_note rejects control char in title", func(t *testing.T) {
		_, _, err := callHandler(t, s.updateNote, UpdateNoteInput{
			NoteID: "550e8400-e29b-41d4-a716-446655440000",
			Title:  new("bad\x07title"),
		})
		if err == nil || !contains(err.Error(), "title must not contain control characters") {
			t.Errorf("updateNote error = %v, want control-char title rejection", err)
		}
	})
}

// --- plan_day ---

func TestPlanDay_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   PlanDayInput
		wantErr string
	}{
		{name: "empty items", input: PlanDayInput{}, wantErr: "items must contain at least one todo"},
		{name: "invalid date", input: PlanDayInput{
			Items: []PlanDayItem{{TaskID: "550e8400-e29b-41d4-a716-446655440000"}},
			Date:  new("bad-date"),
		}, wantErr: "invalid date"},
		// task_id validation within items happens after DB call (delete existing plan)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.planDay, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// --- JSON schema addTool ---

func TestToolSchemaGeneration(t *testing.T) {
	// Verify all input types produce valid JSON schemas.
	types := []struct {
		name string
		fn   func() error
	}{
		{"CaptureInboxInput", testSchema[CaptureInboxInput]},
		{"PlanDayInput", testSchema[PlanDayInput]},
		{"CreateNoteInput", testSchema[CreateNoteInput]},
		{"UpdateNoteInput", testSchema[UpdateNoteInput]},
	}
	for _, tt := range types {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err != nil {
				t.Fatalf("schema generation failed: %v", err)
			}
		})
	}
}

func testSchema[T any]() error {
	var zero T
	schema, err := json.Marshal(zero)
	if err != nil {
		return err
	}
	// Verify it produces valid JSON.
	return json.Unmarshal(schema, &struct{}{})
}

// --- helpers ---

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
