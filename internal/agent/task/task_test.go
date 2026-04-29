package task

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTask_MetadataMarshalsInline locks in the JSONB ↔ JSON wire-shape
// invariant: Task.Metadata is json.RawMessage (not []byte), so Go's
// encoder inlines it instead of base64-encoding. Without this guarantee
// every task surface (task_detail, morning_context.pending_tasks_*)
// returns "metadata":"e30=" instead of "metadata":{}.
func TestTask_MetadataMarshalsInline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		metadata   json.RawMessage
		wantInJSON string
	}{
		{
			name:       "object",
			metadata:   json.RawMessage(`{"foo":"bar"}`),
			wantInJSON: `"metadata":{"foo":"bar"}`,
		},
		{
			name:       "empty object",
			metadata:   json.RawMessage(`{}`),
			wantInJSON: `"metadata":{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(Task{Metadata: tt.metadata})
			if err != nil {
				t.Fatalf("json.Marshal(Task{...}) error = %v, want nil", err)
			}
			if !strings.Contains(string(got), tt.wantInJSON) {
				t.Errorf("Task JSON = %s, want substring %q", got, tt.wantInJSON)
			}
			// Defence against regression to []byte: any base64-shaped value
			// for an empty / object metadata would be either "e30=" or a
			// quoted base64 string. RawMessage marshals the raw bytes inline.
			if strings.Contains(string(got), `"metadata":"e30="`) {
				t.Errorf("Task.Metadata reverted to []byte (base64): %s", got)
			}
		})
	}
}
