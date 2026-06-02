// Copyright 2026 Koopa. All rights reserved.

package task

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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

// Track 1B — Today fan-out wire contract.
//
// GET /api/admin/coordination/tasks/completed (paged {data,meta} envelope) is
// one of the six Today fan-out sources. TaskService.completed() →
// TodayService taskRow() consumes id/title/source/target/submitted_at and
// completed_at (with a submitted_at fallback). These marshaling tests pin the
// Task wire field names and the completed_at omitempty contract without a
// database.

func TestTaskWireContract(t *testing.T) {
	now := time.Date(2026, 5, 19, 4, 0, 0, 0, time.UTC)
	task := Task{
		ID:          uuid.New(),
		Source:      "hq",
		Target:      "research-lab",
		Title:       "Industry scan Q2",
		SubmittedAt: now.Add(-48 * time.Hour),
		CompletedAt: &now,
	}
	keys := taskWireKeys(t, task)
	for _, want := range []string{"id", "source", "target", "title", "state", "submitted_at", "completed_at"} {
		if _, ok := keys[want]; !ok {
			t.Errorf("Task missing wire field %q (TodayService taskRow consumes it)", want)
		}
	}
}

// TestTaskCompletedAtOmittedWhenNil pins the omitempty contract the frontend
// relies on: an in-flight task has no completed_at, and TodayService taskRow
// falls back to submitted_at (`t.completed_at ?? t.submitted_at`). submitted_at
// must always be present.
func TestTaskCompletedAtOmittedWhenNil(t *testing.T) {
	task := Task{ID: uuid.New(), Source: "hq", Target: "research-lab", Title: "open work", SubmittedAt: time.Now()}
	keys := taskWireKeys(t, task)
	if _, ok := keys["completed_at"]; ok {
		t.Error("completed_at must be omitted when nil (frontend falls back to submitted_at)")
	}
	if _, ok := keys["submitted_at"]; !ok {
		t.Error("submitted_at must always be present")
	}
}

func taskWireKeys(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}
