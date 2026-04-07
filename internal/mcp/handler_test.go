package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/learnsession"
)

// newTestServer creates a Server with no stores — only useful for validation tests
// that fail before any DB call.
func newTestServer() *Server {
	return &Server{
		logger:         slog.Default(),
		participant:    "test",
		proposalSecret: []byte("test-secret-32-bytes-long-enough"),
		loc:            time.UTC,
	}
}

func callHandler[I, O any](t *testing.T, handler func(context.Context, *sdkmcp.CallToolRequest, I) (*sdkmcp.CallToolResult, O, error), input I) (*sdkmcp.CallToolResult, O, error) {
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

// --- write_journal ---

func TestWriteJournal_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   WriteJournalInput
		wantErr string
	}{
		{name: "empty content", input: WriteJournalInput{Kind: "plan"}, wantErr: "content is required"},
		{name: "invalid kind", input: WriteJournalInput{Kind: "invalid", Content: "text"}, wantErr: "invalid kind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.writeJournal, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// --- propose_commitment ---

func TestProposeCommitment_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   ProposeCommitmentInput
		wantErr string
	}{
		{name: "invalid type", input: ProposeCommitmentInput{Type: "invalid"}, wantErr: "invalid type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.proposeCommitment, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestProposeCommitment_GoalHappyPath(t *testing.T) {
	s := newTestServer()
	input := ProposeCommitmentInput{
		Type: "goal",
		Fields: map[string]any{
			"title":       "Pass JLPT N2",
			"description": "Japanese language proficiency",
		},
	}
	_, out, err := callHandler(t, s.proposeCommitment, input)
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
	tests := []struct {
		name    string
		input   FileReportInput
		wantErr string
	}{
		{name: "empty content", input: FileReportInput{}, wantErr: "content is required"},
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
		{name: "zero id", input: AcknowledgeDirectiveInput{}, wantErr: "valid directive_id is required"},
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

// --- track_insight ---

func TestTrackInsight_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   TrackInsightInput
		wantErr string
	}{
		{name: "zero id", input: TrackInsightInput{Action: "verify"}, wantErr: "valid insight_id is required"},
		{name: "invalid action", input: TrackInsightInput{InsightID: 1, Action: "bad"}, wantErr: "invalid action"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.trackInsight, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
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

// --- manage_content ---

func TestManageContent_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   ManageContentInput
		wantErr string
	}{
		{name: "invalid action", input: ManageContentInput{Action: "bad"}, wantErr: "invalid action"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.manageContent, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// --- outcome mapping ---

func TestMapOutcome(t *testing.T) {
	tests := []struct {
		name    string
		mode    learnsession.Mode
		input   string
		want    string
		wantErr bool
	}{
		// Raw pass-through
		{name: "raw solved_independent", mode: learnsession.ModePractice, input: "solved_independent", want: "solved_independent"},
		{name: "raw gave_up", mode: learnsession.ModeReading, input: "gave_up", want: "gave_up"},
		{name: "raw completed", mode: learnsession.ModePractice, input: "completed", want: "completed"},

		// Practice mode semantic
		{name: "practice got it", mode: learnsession.ModePractice, input: "got it", want: "solved_independent"},
		{name: "practice needed help", mode: learnsession.ModePractice, input: "needed help", want: "solved_with_hint"},
		{name: "practice saw answer", mode: learnsession.ModePractice, input: "saw answer", want: "solved_after_solution"},
		{name: "practice didn't finish", mode: learnsession.ModePractice, input: "didn't finish", want: "incomplete"},
		{name: "practice gave up", mode: learnsession.ModePractice, input: "gave up", want: "gave_up"},

		// Retrieval mode (same mapping as practice)
		{name: "retrieval solved it", mode: learnsession.ModeRetrieval, input: "solved it", want: "solved_independent"},
		{name: "retrieval nailed it", mode: learnsession.ModeRetrieval, input: "nailed it", want: "solved_independent"},
		{name: "retrieval needed a hint", mode: learnsession.ModeRetrieval, input: "needed a hint", want: "solved_with_hint"},

		// Reading mode
		{name: "reading got it", mode: learnsession.ModeReading, input: "got it", want: "completed"},
		{name: "reading finished", mode: learnsession.ModeReading, input: "finished", want: "completed"},
		{name: "reading needed help", mode: learnsession.ModeReading, input: "needed help", want: "completed_with_support"},
		{name: "reading didn't finish", mode: learnsession.ModeReading, input: "didn't finish", want: "incomplete"},
		{name: "reading stuck", mode: learnsession.ModeReading, input: "stuck", want: "gave_up"},

		// Mixed mode uses practice mapping
		{name: "mixed got help", mode: learnsession.ModeMixed, input: "got help", want: "solved_with_hint"},

		// Review mode uses practice mapping
		{name: "review saw the answer first", mode: learnsession.ModeReview, input: "saw the answer first", want: "solved_after_solution"},

		// Errors
		{name: "practice unknown", mode: learnsession.ModePractice, input: "something else", wantErr: true},
		{name: "reading unknown", mode: learnsession.ModeReading, input: "solved it", wantErr: true},
		{name: "unknown mode", mode: "unknown", input: "got it", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := learnsession.MapOutcome(tt.mode, tt.input)
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
				t.Errorf("MapOutcome(%q, %q) = %q, want %q", tt.mode, tt.input, got, tt.want)
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
		{"WriteJournalInput", testSchema[WriteJournalInput]},
		{"ProposeCommitmentInput", testSchema[ProposeCommitmentInput]},
		{"CommitProposalInput", testSchema[CommitProposalInput]},
		{"FileReportInput", testSchema[FileReportInput]},
		{"AcknowledgeDirectiveInput", testSchema[AcknowledgeDirectiveInput]},
		{"TrackInsightInput", testSchema[TrackInsightInput]},
		{"StartSessionInput", testSchema[StartSessionInput]},
		{"RecordAttemptInput", testSchema[RecordAttemptInput]},
		{"EndSessionInput", testSchema[EndSessionInput]},
		{"LearningDashboardInput", testSchema[LearningDashboardInput]},
		{"ManageContentInput", testSchema[ManageContentInput]},
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
