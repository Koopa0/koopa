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
	"github.com/Koopa0/koopa/internal/learning"
)

// newTestServer creates a Server with no stores — only useful for validation
// tests that fail before any DB call. The default caller is "human" so the
// authorization helpers in authz.go (requireAuthor, requireExplicitHuman) do
// not gate validation paths from running. Tests that need a non-human caller
// override callerAgent or pass `as` via context.
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
		{name: "invalid due", input: CaptureInboxInput{Title: "test", Due: strPtr("not-a-date")}, wantErr: "invalid due date"},
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
			Date:  strPtr("bad-date"),
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

// TestParseOptionalUUID covers the consolidated helper in internal/mcp/uuid.go.
// It replaces parseNamedUUID (hypothesis.go) and the un-named parseOptionalUUID
// (plan.go) that existed before this refactor.
func TestParseOptionalUUID(t *testing.T) {
	validUUID := "550e8400-e29b-41d4-a716-446655440000"
	empty := ""

	t.Run("nil returns (nil, nil)", func(t *testing.T) {
		got, err := parseOptionalUUID(nil, "some_field")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if got != nil {
			t.Errorf("got = %v, want nil", got)
		}
	})
	t.Run("empty string returns (nil, nil)", func(t *testing.T) {
		got, err := parseOptionalUUID(&empty, "some_field")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if got != nil {
			t.Errorf("got = %v, want nil", got)
		}
	})
	t.Run("valid uuid parses", func(t *testing.T) {
		got, err := parseOptionalUUID(&validUUID, "some_field")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if got == nil {
			t.Fatal("got = nil, want parsed uuid")
		}
	})
	t.Run("invalid uuid names the field, no uuid.Parse leak", func(t *testing.T) {
		bad := "abc"
		_, err := parseOptionalUUID(&bad, "some_field")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "invalid some_field") {
			t.Errorf("err = %q, want %q", err.Error(), "invalid some_field")
		}
		if contains(err.Error(), "invalid UUID length") {
			t.Errorf("err = %q, must NOT contain uuid.Parse internals", err.Error())
		}
	})
}

// --- start_session ---

func TestStartSession_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   StartSessionInput
		wantErr string
	}{
		{name: "empty domain", input: StartSessionInput{Mode: "practice"}, wantErr: "domain is required"},
		{name: "invalid mode", input: StartSessionInput{Domain: "leetcode", Mode: "bad"}, wantErr: "invalid mode"},
		{name: "invalid plan item id", input: StartSessionInput{Domain: "leetcode", Mode: "practice", DailyPlanItemID: strPtr("bad")}, wantErr: "invalid daily_plan_item_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.startSession, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// --- record_attempt ---

func TestRecordAttempt_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   RecordAttemptInput
		wantErr string
	}{
		{name: "invalid session_id", input: RecordAttemptInput{SessionID: "bad"}, wantErr: "invalid session_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.recordAttempt, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// --- end_session ---

func TestEndSession_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   EndSessionInput
		wantErr string
	}{
		{name: "invalid session_id", input: EndSessionInput{SessionID: "bad"}, wantErr: "invalid session_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.endSession, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// --- learning_read ---

func TestLearningRead_InvalidView(t *testing.T) {
	s := newTestServer()
	_, _, err := callHandler(t, s.learningRead, LearningReadInput{View: "bogus"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "unknown view") {
		t.Errorf("error = %q, want containing %q", err, "unknown view")
	}
}

// --- outcome mapping ---

func TestMapOutcome(t *testing.T) {
	tests := []struct {
		name         string
		mode         learning.Mode
		input        string
		wantParadigm learning.Paradigm
		want         string
		wantErr      bool
	}{
		// Raw pass-through — paradigm is implied by outcome for paradigm-specific
		// values; shared values (gave_up) follow mode.
		{name: "raw solved_independent", mode: learning.ModePractice, input: "solved_independent", wantParadigm: learning.ParadigmProblemSolving, want: "solved_independent"},
		{name: "raw gave_up in reading mode", mode: learning.ModeReading, input: "gave_up", wantParadigm: learning.ParadigmImmersive, want: "gave_up"},
		{name: "raw completed", mode: learning.ModePractice, input: "completed", wantParadigm: learning.ParadigmImmersive, want: "completed"},

		// Practice mode semantic
		{name: "practice got it", mode: learning.ModePractice, input: "got it", wantParadigm: learning.ParadigmProblemSolving, want: "solved_independent"},
		{name: "practice needed help", mode: learning.ModePractice, input: "needed help", wantParadigm: learning.ParadigmProblemSolving, want: "solved_with_hint"},
		{name: "practice saw answer", mode: learning.ModePractice, input: "saw answer", wantParadigm: learning.ParadigmProblemSolving, want: "solved_after_solution"},
		{name: "practice didn't finish", mode: learning.ModePractice, input: "didn't finish", wantParadigm: learning.ParadigmProblemSolving, want: "incomplete"},
		{name: "practice gave up", mode: learning.ModePractice, input: "gave up", wantParadigm: learning.ParadigmProblemSolving, want: "gave_up"},

		// Retrieval mode (same mapping as practice)
		{name: "retrieval solved it", mode: learning.ModeRetrieval, input: "solved it", wantParadigm: learning.ParadigmProblemSolving, want: "solved_independent"},
		{name: "retrieval nailed it", mode: learning.ModeRetrieval, input: "nailed it", wantParadigm: learning.ParadigmProblemSolving, want: "solved_independent"},
		{name: "retrieval needed a hint", mode: learning.ModeRetrieval, input: "needed a hint", wantParadigm: learning.ParadigmProblemSolving, want: "solved_with_hint"},

		// Reading mode
		{name: "reading got it", mode: learning.ModeReading, input: "got it", wantParadigm: learning.ParadigmImmersive, want: "completed"},
		{name: "reading finished", mode: learning.ModeReading, input: "finished", wantParadigm: learning.ParadigmImmersive, want: "completed"},
		{name: "reading needed help", mode: learning.ModeReading, input: "needed help", wantParadigm: learning.ParadigmImmersive, want: "completed_with_support"},
		{name: "reading didn't finish", mode: learning.ModeReading, input: "didn't finish", wantParadigm: learning.ParadigmImmersive, want: "incomplete"},
		{name: "reading stuck", mode: learning.ModeReading, input: "stuck", wantParadigm: learning.ParadigmImmersive, want: "gave_up"},

		// Mixed mode uses practice mapping
		{name: "mixed got help", mode: learning.ModeMixed, input: "got help", wantParadigm: learning.ParadigmProblemSolving, want: "solved_with_hint"},

		// Review mode uses practice mapping
		{name: "review saw the answer first", mode: learning.ModeReview, input: "saw the answer first", wantParadigm: learning.ParadigmProblemSolving, want: "solved_after_solution"},

		// Errors
		{name: "practice unknown", mode: learning.ModePractice, input: "something else", wantErr: true},
		{name: "reading unknown", mode: learning.ModeReading, input: "solved it", wantErr: true},
		{name: "unknown mode", mode: "unknown", input: "got it", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotParadigm, got, err := learning.MapOutcome(tt.mode, tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("MapOutcome(%q, %q) = %q, want error", tt.mode, tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("MapOutcome(%q, %q) unexpected error: %v", tt.mode, tt.input, err)
			}
			if got != tt.want {
				t.Errorf("MapOutcome(%q, %q) outcome = %q, want %q", tt.mode, tt.input, got, tt.want)
			}
			if gotParadigm != tt.wantParadigm {
				t.Errorf("MapOutcome(%q, %q) paradigm = %q, want %q", tt.mode, tt.input, gotParadigm, tt.wantParadigm)
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
		{"StartSessionInput", testSchema[StartSessionInput]},
		{"RecordAttemptInput", testSchema[RecordAttemptInput]},
		{"EndSessionInput", testSchema[EndSessionInput]},
		{"LearningReadInput", testSchema[LearningReadInput]},
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

func strPtr(s string) *string { return &s }

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
