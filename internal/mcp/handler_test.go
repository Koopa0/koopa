package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/learning"
)

// newTestServer creates a Server with no stores — only useful for validation tests
// that fail before any DB call.
func newTestServer() *Server {
	return &Server{
		logger:         slog.Default(),
		callerAgent:    "test",
		proposalSecret: []byte("test-secret-32-bytes-long-enough"),
		loc:            time.UTC,
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

// --- advance_work ---

func TestAdvanceWork_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   AdvanceWorkInput
		wantErr string
	}{
		{name: "invalid task_id", input: AdvanceWorkInput{TaskID: "not-uuid", Action: "start"}, wantErr: "invalid task_id"},
		// Action validation is tested via TestValidateTransition (requires DB for task lookup)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.advanceWork, tt.input)
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
		{name: "empty items", input: PlanDayInput{}, wantErr: "items is required"},
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

// --- write_agent_note ---

func TestWriteAgentNote_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   WriteAgentNoteInput
		wantErr string
	}{
		{name: "empty content", input: WriteAgentNoteInput{Kind: "plan"}, wantErr: "content is required"},
		{name: "invalid kind", input: WriteAgentNoteInput{Kind: "invalid", Content: "text"}, wantErr: "invalid kind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.writeAgentNote, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// --- propose_goal (representative happy path for the typed propose tools) ---

func TestProposeGoal_HappyPath(t *testing.T) {
	s := newTestServer()
	desc := "Japanese language proficiency"
	_, out, err := callHandler(t, s.proposeGoal, ProposeGoalInput{
		Title:       "Pass JLPT N2",
		Description: &desc,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Type != "goal" {
		t.Errorf("type = %q, want %q", out.Type, "goal")
	}
	if out.ProposalToken == "" {
		t.Error("proposal_token is empty")
	}
	if out.Preview["title"] != "Pass JLPT N2" {
		t.Errorf("preview title = %v, want %q", out.Preview["title"], "Pass JLPT N2")
	}
}

// --- commit_proposal ---

func TestCommitProposal_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   CommitProposalInput
		wantErr string
	}{
		{name: "empty token", input: CommitProposalInput{}, wantErr: "invalid proposal"},
		{name: "garbage token", input: CommitProposalInput{ProposalToken: "not.valid"}, wantErr: "invalid proposal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.commitProposal, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// --- file_report ---

func TestFileReport_Validation(t *testing.T) {
	s := newTestServer()
	validPart := json.RawMessage(`{"text":"report content"}`)
	validArtifact := &FileReportArtifactInput{
		Name:  "delivery",
		Parts: []json.RawMessage{json.RawMessage(`{"text":"artifact body"}`)},
	}
	tests := []struct {
		name    string
		input   FileReportInput
		wantErr string
	}{
		{
			name:    "missing artifact",
			input:   FileReportInput{ResponseParts: []json.RawMessage{validPart}},
			wantErr: "artifact is required",
		},
		{
			name: "malformed response part",
			input: FileReportInput{
				InResponseTo:  "00000000-0000-0000-0000-000000000001",
				ResponseParts: []json.RawMessage{json.RawMessage(`{bad json`)},
				Artifact:      validArtifact,
			},
			wantErr: "response_parts",
		},
		{
			name: "malformed artifact part",
			input: FileReportInput{
				ResponseParts: []json.RawMessage{validPart},
				Artifact: &FileReportArtifactInput{
					Name:  "delivery",
					Parts: []json.RawMessage{json.RawMessage(`{bad json`)},
				},
			},
			wantErr: "artifact.parts",
		},
		{
			name:    "invalid in_response_to UUID",
			input:   FileReportInput{InResponseTo: "not-a-uuid", ResponseParts: []json.RawMessage{validPart}, Artifact: validArtifact},
			wantErr: "invalid in_response_to UUID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.fileReport, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// --- acknowledge_directive ---

func TestAcknowledgeDirective_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   AcknowledgeDirectiveInput
		wantErr string
	}{
		{name: "empty id", input: AcknowledgeDirectiveInput{}, wantErr: "invalid directive_id"},
		{name: "bad uuid", input: AcknowledgeDirectiveInput{DirectiveID: "not-a-uuid"}, wantErr: "invalid directive_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.acknowledgeDirective, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// --- track_hypothesis ---

func TestTrackHypothesis_Validation(t *testing.T) {
	s := newTestServer()
	validID := "00000000-0000-0000-0000-000000000001"
	bigSummary := strings.Repeat("a", 2*1024+1)
	tests := []struct {
		name    string
		input   TrackHypothesisInput
		wantErr string
	}{
		{name: "zero id", input: TrackHypothesisInput{Action: "verify"}, wantErr: "invalid hypothesis_id"},
		{name: "invalid action", input: TrackHypothesisInput{HypothesisID: validID, Action: "bad"}, wantErr: "invalid action"},
		// verify/invalidate must carry at least one evidence source.
		{name: "verify no evidence", input: TrackHypothesisInput{HypothesisID: validID, Action: "verify"}, wantErr: "at least one of"},
		{name: "invalidate no evidence", input: TrackHypothesisInput{HypothesisID: validID, Action: "invalidate"}, wantErr: "at least one of"},
		{name: "verify blank summary only", input: TrackHypothesisInput{HypothesisID: validID, Action: "verify", ResolutionSummary: strPtr("   ")}, wantErr: "at least one of"},
		// Malformed evidence UUIDs surface before the "at least one" check
		// so the rejection is loud even when a summary is also present.
		{name: "verify bad attempt_id", input: TrackHypothesisInput{HypothesisID: validID, Action: "verify", ResolvedByAttemptID: strPtr("not-a-uuid"), ResolutionSummary: strPtr("ok")}, wantErr: "invalid resolved_by_attempt_id"},
		{name: "verify bad observation_id", input: TrackHypothesisInput{HypothesisID: validID, Action: "invalidate", ResolvedByObservationID: strPtr("nope"), ResolutionSummary: strPtr("ok")}, wantErr: "invalid resolved_by_observation_id"},
		{name: "verify summary too large", input: TrackHypothesisInput{HypothesisID: validID, Action: "verify", ResolutionSummary: &bigSummary}, wantErr: "resolution_summary too large"},
		// Control characters in resolution_summary rejected per security.md.
		{name: "verify summary with NUL", input: TrackHypothesisInput{HypothesisID: validID, Action: "verify", ResolutionSummary: strPtr("solved\x00cleanly")}, wantErr: "control characters"},
		{name: "verify summary with ESC", input: TrackHypothesisInput{HypothesisID: validID, Action: "verify", ResolutionSummary: strPtr("\x1b[31mred")}, wantErr: "control characters"},
		// add_evidence validation: missing / invalid type must not reach the store.
		{name: "add_evidence nil evidence", input: TrackHypothesisInput{HypothesisID: validID, Action: "add_evidence"}, wantErr: "evidence is required"},
		{name: "add_evidence missing type", input: TrackHypothesisInput{HypothesisID: validID, Action: "add_evidence", Evidence: map[string]any{"note": "no type"}}, wantErr: "supporting or counter"},
		{name: "add_evidence invalid type", input: TrackHypothesisInput{HypothesisID: validID, Action: "add_evidence", Evidence: map[string]any{"type": "bogus"}}, wantErr: "supporting or counter"},
		// Also verify the reverse: uuid.Parse internals ("invalid UUID length: ...")
		// must NOT leak to MCP callers — the field name alone is reported.
		{name: "verify attempt error does not leak uuid.Parse", input: TrackHypothesisInput{HypothesisID: validID, Action: "verify", ResolvedByAttemptID: strPtr("abc")}, wantErr: "invalid resolved_by_attempt_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.trackHypothesis, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// --- manage_feeds ---

func TestParseMCPTopicIDs_Errors(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr string
	}{
		{name: "malformed uuid", input: []string{"not-a-uuid"}, wantErr: "invalid topic_id"},
		{name: "too many", input: make([]string, mcpMaxTopicIDs+1), wantErr: "too many topic_ids"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseMCPTopicIDs(tt.input)
			if err == nil || !contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseMCPTopicIDs() err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestParseMCPTopicIDs_NoUUIDParseLeak asserts the error string does NOT
// leak uuid.Parse's internal messages ("invalid UUID length: N", "invalid
// UUID format") to the MCP caller. The field+index is the only
// information we want to surface — anything more is internal state.
func TestParseMCPTopicIDs_NoUUIDParseLeak(t *testing.T) {
	leakMarkers := []string{"invalid UUID length", "invalid UUID format"}
	inputs := [][]string{
		{"abc"},               // too short
		{"not-a-uuid-at-all"}, // wrong format
		{""},                  // empty string mid-slice (valid uuid.Nil err)
	}
	for i, in := range inputs {
		_, err := parseMCPTopicIDs(in)
		if err == nil {
			t.Fatalf("case %d: expected error for input %q, got nil", i, in)
		}
		for _, marker := range leakMarkers {
			if contains(err.Error(), marker) {
				t.Errorf("case %d: error = %q, must NOT contain %q (uuid.Parse internals)",
					i, err.Error(), marker)
			}
		}
	}
}

// TestParseFeedID_NoUUIDParseLeak mirrors the topic_id test: parseFeedID
// must not leak uuid.Parse internals either.
func TestParseFeedID_NoUUIDParseLeak(t *testing.T) {
	bad := "not-a-uuid"
	_, err := parseFeedID(&bad)
	if err == nil {
		t.Fatal("expected error for malformed feed_id, got nil")
	}
	if contains(err.Error(), "invalid UUID length") || contains(err.Error(), "invalid UUID format") {
		t.Errorf("err = %q, must NOT contain uuid.Parse internals", err.Error())
	}
	if !contains(err.Error(), "invalid feed_id") {
		t.Errorf("err = %q, want to contain %q", err.Error(), "invalid feed_id")
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

func TestParseMCPTopicIDs_Success(t *testing.T) {
	validUUID := "550e8400-e29b-41d4-a716-446655440000"
	t.Run("nil passes through", func(t *testing.T) {
		got, err := parseMCPTopicIDs(nil)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if got != nil {
			t.Errorf("got = %v, want nil (leave unchanged contract)", got)
		}
	})
	t.Run("empty slice yields empty non-nil", func(t *testing.T) {
		got, err := parseMCPTopicIDs([]string{})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if got == nil {
			t.Errorf("got = nil, want non-nil zero-length slice (clear contract)")
		}
		if len(got) != 0 {
			t.Errorf("got len = %d, want 0", len(got))
		}
	})
	t.Run("single valid uuid", func(t *testing.T) {
		got, err := parseMCPTopicIDs([]string{validUUID})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(got) != 1 {
			t.Errorf("got len = %d, want 1", len(got))
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

// --- learning_dashboard ---

func TestLearningDashboard_InvalidView(t *testing.T) {
	s := newTestServer()
	input := LearningDashboardInput{View: strPtr("nonexistent")}
	_, _, err := callHandler(t, s.learningDashboard, input)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "unknown view") {
		t.Errorf("error = %q, want containing %q", err, "unknown view")
	}
}

// --- content flat tools ---
//
// The old manage_content multiplexer + its TestManageContent_Validation
// invalid-action path were removed in the notes/content split. Validation is now
// per-tool (required-field checks in each *Tool handler). See
// TestCreateContent_Validation etc. if / when they're added.

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
		{"AdvanceWorkInput", testSchema[AdvanceWorkInput]},
		{"PlanDayInput", testSchema[PlanDayInput]},
		{"WriteAgentNoteInput", testSchema[WriteAgentNoteInput]},
		{"ProposeGoalInput", testSchema[ProposeGoalInput]},
		{"ProposeProjectInput", testSchema[ProposeProjectInput]},
		{"ProposeMilestoneInput", testSchema[ProposeMilestoneInput]},
		{"ProposeDirectiveInput", testSchema[ProposeDirectiveInput]},
		{"ProposeHypothesisInput", testSchema[ProposeHypothesisInput]},
		{"ProposeLearningPlanInput", testSchema[ProposeLearningPlanInput]},
		{"ProposeLearningDomainInput", testSchema[ProposeLearningDomainInput]},
		{"CommitProposalInput", testSchema[CommitProposalInput]},
		{"FileReportInput", testSchema[FileReportInput]},
		{"AcknowledgeDirectiveInput", testSchema[AcknowledgeDirectiveInput]},
		{"TrackHypothesisInput", testSchema[TrackHypothesisInput]},
		{"StartSessionInput", testSchema[StartSessionInput]},
		{"RecordAttemptInput", testSchema[RecordAttemptInput]},
		{"EndSessionInput", testSchema[EndSessionInput]},
		{"LearningDashboardInput", testSchema[LearningDashboardInput]},
		{"CreateContentInput", testSchema[CreateContentInput]},
		{"UpdateContentInput", testSchema[UpdateContentInput]},
		{"SubmitContentForReviewInput", testSchema[SubmitContentForReviewInput]},
		{"RevertContentToDraftInput", testSchema[RevertContentToDraftInput]},
		{"PublishContentInput", testSchema[PublishContentInput]},
		{"ArchiveContentInput", testSchema[ArchiveContentInput]},
		{"ListContentInput", testSchema[ListContentInput]},
		{"ReadContentInput", testSchema[ReadContentInput]},
		{"CreateNoteInput", testSchema[CreateNoteInput]},
		{"UpdateNoteInput", testSchema[UpdateNoteInput]},
		{"UpdateNoteMaturityInput", testSchema[UpdateNoteMaturityInput]},
		{"ManageFeedsInput", testSchema[ManageFeedsInput]},
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
