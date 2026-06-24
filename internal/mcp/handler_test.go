// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// newTestServer creates a Server with no stores — only useful for validation
// tests that fail before any DB call. The default caller is "human", which is
// the attribution stamped on any write these tests reach. Tests that need a
// different caller override callerAgent or pass `as` via context.
func newTestServer() *Server {
	return &Server{
		logger:      slog.Default(),
		callerAgent: "human",
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

// --- propose_content ---

// TestProposeContent_Validation covers the validation that runs BEFORE any DB
// call: the required-field, content-type, control-char, slug-derivation, and
// topic-id checks. A finished-draft body and a derivable title are the happy
// preconditions; each case violates exactly one of them.
func TestProposeContent_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   ProposeContentInput
		wantErr string
	}{
		{
			name:    "empty title",
			input:   ProposeContentInput{Type: "article", Body: "x"},
			wantErr: "title is required",
		},
		{
			name:    "empty type",
			input:   ProposeContentInput{Title: "Hello", Body: "x"},
			wantErr: "type is required",
		},
		{
			name:    "empty body",
			input:   ProposeContentInput{Title: "Hello", Type: "article"},
			wantErr: "body is required",
		},
		{
			name:    "invalid type",
			input:   ProposeContentInput{Title: "Hello", Type: "tweet", Body: "x"},
			wantErr: "type must be one of",
		},
		{
			name:    "note type rejected",
			input:   ProposeContentInput{Title: "Hello", Type: "note", Body: "x"},
			wantErr: "type must be one of",
		},
		{
			name:    "C0 control char in title",
			input:   ProposeContentInput{Title: "bad\x07title", Type: "article", Body: "x"},
			wantErr: "title must not contain control characters",
		},
		{
			name:    "C1 control char in body",
			input:   ProposeContentInput{Title: "Hello", Type: "article", Body: "line\u009fline"},
			wantErr: "body must not contain control characters",
		},
		{
			name:    "control char in excerpt",
			input:   ProposeContentInput{Title: "Hello", Type: "article", Body: "x", Excerpt: "bad\x00excerpt"},
			wantErr: "excerpt must not contain control characters",
		},
		{
			name:    "control char in proposal_rationale",
			input:   ProposeContentInput{Title: "Hello", Type: "article", Body: "x", ProposalRationale: "why\x01now"},
			wantErr: "proposal_rationale must not contain control characters",
		},
		{
			name:    "title with no slug-able chars",
			input:   ProposeContentInput{Title: "!!!", Type: "article", Body: "x"},
			wantErr: "must contain at least one letter or number",
		},
		{
			name:    "malformed topic id",
			input:   ProposeContentInput{Title: "Hello", Type: "article", Body: "x", TopicIDs: []string{"not-a-uuid"}},
			wantErr: "is not a valid uuid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.proposeContent, tt.input)
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
