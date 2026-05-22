package mcp

import "testing"

// Unit tests for the A2A coordination tools (a2a.go) — DB-free dimensions.
//
// The file_report and acknowledge_directive pre-DB validation paths are
// covered in handler_test.go (TestFileReport_Validation,
// TestAcknowledgeDirective_Validation); the propose_directive title contract
// is covered in commitment_test.go (TestExtractTitleFromFirstTextPart). This
// file fills the one remaining CI-visible gap: task_detail rejects a malformed
// task_id at the parsing boundary, before any store call, so a nil-store
// newTestServer() is sufficient and the check runs in the default
// `go test ./...` lane (the integration suite also pins it under build tag,
// but that lane does not run in first-signal CI).
//
// DB-backed behavior (the directive→ack→report chain, conflicts, actor
// enforcement, not-found, state edges) lives in a2a_integration_test.go.

func TestTaskDetail_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   TaskDetailInput
		wantErr string
	}{
		{name: "empty task_id", input: TaskDetailInput{}, wantErr: "invalid task_id"},
		{name: "malformed task_id", input: TaskDetailInput{TaskID: "not-a-uuid"}, wantErr: "invalid task_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.taskDetail, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}
