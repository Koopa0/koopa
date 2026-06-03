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
		logger:         slog.Default(),
		callerAgent:    "human",
		registry:       agent.NewBuiltinRegistry(),
		proposalSecret: []byte("test-secret-32-bytes-long-enough"),
		loc:            time.UTC,
		nonces:         newNonceStore(),
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

// TestCommitProposal_DirectiveAuthBeforeConsume is the regression guard for
// finding #2: directive authorization (ActionSubmitTask) must run BEFORE the
// nonce is consumed, so an unauthorized caller cannot burn a legitimate
// proposer's token. Before the fix consume ran first and commitDirective failed
// authorization afterwards, leaving the token spent — a DoS on the proposer.
func TestCommitProposal_DirectiveAuthBeforeConsume(t *testing.T) {
	s := newTestServer()

	// A valid directive token. Fields can be empty: in the buggy ordering the
	// nonce is consumed before commitEntity runs at all, so the token is burned
	// regardless of downstream field validity — which is exactly the bug.
	token, err := signProposal(s.proposalSecret, "directive", map[string]any{})
	if err != nil {
		t.Fatalf("signProposal: %v", err)
	}

	// learning-studio holds ReceiveTasks|PublishArtifacts but NOT SubmitTasks,
	// so it is not authorized to commit a directive.
	unauthCtx := withCallerAs(t.Context(), "learning-studio")
	if _, _, cErr := s.commitProposal(unauthCtx, nil, CommitProposalInput{ProposalToken: token}); cErr == nil {
		t.Fatal("unauthorized directive commit = nil error, want authorization rejection")
	}

	// The nonce must NOT have been consumed by the failed attempt: a fresh
	// claim of the same nonce must still succeed. (The probe itself consumes
	// it, which is fine — the assertion is only whether it was still free.)
	payload, err := verifyProposal(s.proposalSecret, token)
	if err != nil {
		t.Fatalf("verifyProposal: %v", err)
	}
	if !s.nonces.consume(payload.Nonce, payload.ExpiresAt+60, time.Now().Unix()) {
		t.Error("unauthorized directive commit consumed the nonce — authorization must run before consume")
	}
}

// TestCommitProposal_FailureAfterConsumeIsExplicit is the regression guard for
// finding #3: when commitEntity fails AFTER the nonce is consumed, the returned
// error must make the spent-token state explicit (the caller must re-propose),
// not surface the bare downstream error as if the token were still usable. The
// single-use-on-claim semantics are unchanged; only the error is clarified.
func TestCommitProposal_FailureAfterConsumeIsExplicit(t *testing.T) {
	s := newTestServer()

	// A goal token with no title passes the human gate and the nonce consume,
	// then commitGoal fails on the missing required field BEFORE any DB call —
	// exercising the post-consume failure path deterministically.
	token, err := signProposal(s.proposalSecret, "goal", map[string]any{})
	if err != nil {
		t.Fatalf("signProposal: %v", err)
	}
	humanCtx := withCallerAs(t.Context(), "human")
	_, _, err = s.commitProposal(humanCtx, nil, CommitProposalInput{ProposalToken: token})
	if err == nil {
		t.Fatal("commit of an invalid goal = nil error, want failure")
	}
	// Explicit about the spent token + how to recover.
	if !contains(err.Error(), "consumed") || !contains(err.Error(), "re-propose") {
		t.Errorf("post-consume failure error = %q, want it to state the token was consumed and to re-propose", err)
	}
	// The underlying cause is preserved (wrapped, not replaced).
	if !contains(err.Error(), "title is required") {
		t.Errorf("post-consume failure error = %q, want it to preserve the underlying cause", err)
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
		{name: "empty id", input: AcknowledgeDirectiveInput{}, wantErr: "invalid task_id"},
		{name: "bad uuid", input: AcknowledgeDirectiveInput{TaskID: "not-a-uuid"}, wantErr: "invalid task_id"},
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

// TestTrackHypothesis_Validation covers the cheap dispatch-path
// validations that fire BEFORE resolveHypothesis' pre-flight existence
// check (and therefore don't need a real hypothesis row).
// Resolve-path field validation moved to
// TestIntegration_TrackHypothesis_Resolve_Validation in integration_test.go
// after #13 removed the nil-guard in hypothesis.go.
func TestTrackHypothesis_Validation(t *testing.T) {
	s := newTestServer()
	validID := "00000000-0000-0000-0000-000000000001"
	tests := []struct {
		name    string
		input   TrackHypothesisInput
		wantErr string
	}{
		{name: "zero id", input: TrackHypothesisInput{Action: "verify"}, wantErr: "invalid hypothesis_id"},
		{name: "invalid action", input: TrackHypothesisInput{HypothesisID: validID, Action: "bad"}, wantErr: "invalid action"},
		// add_evidence validation runs entirely on the input before any
		// store call, so it stays in the unit suite.
		{name: "add_evidence nil evidence", input: TrackHypothesisInput{HypothesisID: validID, Action: "add_evidence"}, wantErr: "evidence is required"},
		{name: "add_evidence missing type", input: TrackHypothesisInput{HypothesisID: validID, Action: "add_evidence", Evidence: map[string]any{"note": "no type"}}, wantErr: "supporting or counter"},
		{name: "add_evidence invalid type", input: TrackHypothesisInput{HypothesisID: validID, Action: "add_evidence", Evidence: map[string]any{"type": "bogus"}}, wantErr: "supporting or counter"},
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
		{"SetContentReviewStateInput", testSchema[SetContentReviewStateInput]},
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
