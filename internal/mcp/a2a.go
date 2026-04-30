// a2a.go holds the coordination-layer MCP tools that translate between
// a2a-go's Part shape and internal/agent/task. Three tool handlers live
// here:
//
//   - acknowledge_directive — target agent accepts an assigned task.
//   - file_report           — target agent completes a task with a
//     response message + artifact (atomic).
//
// The propose_directive source side of the protocol lives in
// propose_flat.go (and shares the proposal-token plumbing in
// commitment.go with the non-directive commitment types).

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/agent/artifact"
	"github.com/Koopa0/koopa/internal/agent/task"
)

// parseA2AParts deserializes a wire-side JSON array of a2a.Part values
// into typed Go values. This is the single entry point for wire→in-memory
// Part conversion across the MCP layer.
func parseA2AParts(raw []json.RawMessage) ([]*a2a.Part, error) {
	out := make([]*a2a.Part, 0, len(raw))
	for i, r := range raw {
		var p a2a.Part
		if err := json.Unmarshal(r, &p); err != nil {
			return nil, fmt.Errorf("parts[%d]: %w", i, err)
		}
		out = append(out, &p)
	}
	return out, nil
}

// --- file_report ---

// FileReportArtifactInput is the structured deliverable attached to a
// file_report call.
type FileReportArtifactInput struct {
	Name        string            `json:"name" jsonschema:"required" jsonschema_description:"Short artifact label (e.g. 'weekly-report', 'architecture-diagram')"`
	Description string            `json:"description,omitempty" jsonschema_description:"Optional longer description"`
	Parts       []json.RawMessage `json:"parts" jsonschema:"required" jsonschema_description:"Artifact content as a2a.Part JSON objects: [{\"text\":\"...\"}] or [{\"data\":{...}}]"`
}

// FileReportInput is the input for the file_report tool.
//
// Caller identity is resolved via callerIdentity(ctx) (the "as" field
// or server default), so no explicit source field is needed.
//
// When InResponseTo is provided the handler completes the referenced
// task atomically (response message + artifact + state transition).
// When absent the handler creates a standalone artifact attributed to
// the caller — no task is involved.
type FileReportInput struct {
	InResponseTo  string                   `json:"in_response_to,omitempty" jsonschema_description:"Task UUID this report responds to. Omit for self-initiated artifacts."`
	ResponseParts []json.RawMessage        `json:"response_parts,omitempty" jsonschema_description:"Response message parts (required when in_response_to is set)."`
	Artifact      *FileReportArtifactInput `json:"artifact" jsonschema:"required" jsonschema_description:"The structured deliverable."`
}

// FileReportOutput is the output of the file_report tool.
type FileReportOutput struct {
	ArtifactID string `json:"artifact_id"`
	TaskID     string `json:"task_id,omitempty"`
	State      string `json:"state"`
	Completed  bool   `json:"completed"`
}

func (s *Server) fileReport(ctx context.Context, _ *mcp.CallToolRequest, input FileReportInput) (*mcp.CallToolResult, FileReportOutput, error) {
	if input.Artifact == nil {
		return nil, FileReportOutput{}, errors.New("file_report: artifact is required")
	}
	artifactParts, err := parseA2AParts(input.Artifact.Parts)
	if err != nil {
		return nil, FileReportOutput{}, fmt.Errorf("file_report: artifact.parts: %w", err)
	}

	caller := agent.Name(s.callerIdentity(ctx))

	// Task-bound path: complete the referenced task with the artifact.
	if input.InResponseTo != "" {
		return s.fileReportWithTask(ctx, caller, input, artifactParts)
	}

	// Standalone path: create artifact without a task.
	return s.fileReportStandalone(ctx, caller, input, artifactParts)
}

// fileReportWithTask completes a task atomically: caller MUST be the
// task's assignee (target). Without the assignee check the only signal
// a non-target caller would see is the task store's generic
// ErrConflict (the TransitionTaskToCompleted UPDATE matches no rows
// when state isn't 'working'). That error is ambiguous between "task
// in wrong state" and "wrong caller". Loading the task first and
// asserting caller == assignee gives an unambiguous error before the
// store ever runs.
func (s *Server) fileReportWithTask(ctx context.Context, caller agent.Name, input FileReportInput, artifactParts []*a2a.Part) (*mcp.CallToolResult, FileReportOutput, error) {
	responseParts, err := parseA2AParts(input.ResponseParts)
	if err != nil {
		return nil, FileReportOutput{}, fmt.Errorf("file_report: response_parts: %w", err)
	}

	taskID, err := uuid.Parse(input.InResponseTo)
	if err != nil {
		return nil, FileReportOutput{}, fmt.Errorf("file_report: invalid in_response_to UUID: %w", err)
	}

	auth, err := agent.Authorize(ctx, s.registry, caller, agent.ActionCompleteTask)
	if err != nil {
		return nil, FileReportOutput{}, fmt.Errorf("file_report: %w", err)
	}

	existing, err := s.tasks.Task(ctx, taskID)
	if err != nil {
		if errors.Is(err, task.ErrNotFound) {
			return nil, FileReportOutput{}, fmt.Errorf("file_report: task %s not found", taskID)
		}
		return nil, FileReportOutput{}, fmt.Errorf("file_report: loading task: %w", err)
	}
	if existing.Target != string(caller) {
		return nil, FileReportOutput{}, fmt.Errorf("file_report: caller %q is not the task target (%q); only the assignee can complete a task", caller, existing.Target)
	}
	if existing.State != task.StateWorking {
		return nil, FileReportOutput{}, fmt.Errorf("file_report: task %s is in state %q; complete only works on tasks in 'working' state (call acknowledge_directive first to move submitted → working)", taskID, existing.State)
	}

	var completed *task.Task
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		completed, err = s.tasks.WithTx(tx).Complete(ctx, auth, &task.CompleteInput{
			TaskID:        taskID,
			ResponseParts: responseParts,
			ArtifactName:  input.Artifact.Name,
			ArtifactDesc:  input.Artifact.Description,
			ArtifactParts: artifactParts,
		})
		return err
	})
	if err != nil {
		return nil, FileReportOutput{}, fmt.Errorf("file_report: %w", err)
	}

	s.logger.Info("file_report", "task_id", taskID, "state", completed.State)
	return nil, FileReportOutput{
		ArtifactID: "", // artifact ID not returned by task.Complete; task_id is the anchor
		TaskID:     completed.ID.String(),
		State:      string(completed.State),
		Completed:  completed.State == task.StateCompleted,
	}, nil
}

// fileReportStandalone creates an artifact not bound to any task. The
// allowlist names the cowork agents whose work has a "standalone
// publishable artifact" shape: content-studio (quarterly content
// reports), research-lab (industry scans without a directive),
// learning-studio (weekly learning summaries). HQ has PublishArtifacts
// capability but no business reason to publish standalone artifacts —
// its outputs are agent_notes (plan/reflection) and read-side aggregates
// (weekly_summary), not artifacts. Excluding HQ here prevents drift
// where HQ accidentally creates artifacts that nobody reads.
func (s *Server) fileReportStandalone(ctx context.Context, caller agent.Name, input FileReportInput, artifactParts []*a2a.Part) (*mcp.CallToolResult, FileReportOutput, error) {
	if err := s.requireAuthor(ctx, "file_report (standalone)", "content-studio", "research-lab", "learning-studio"); err != nil {
		return nil, FileReportOutput{}, err
	}
	auth, err := agent.Authorize(ctx, s.registry, caller, agent.ActionPublishArtifact)
	if err != nil {
		return nil, FileReportOutput{}, fmt.Errorf("file_report: %w", err)
	}

	a, err := s.artifacts.Add(ctx, auth, artifact.AddInput{
		TaskID:      nil,
		CreatedBy:   string(caller),
		Name:        input.Artifact.Name,
		Description: input.Artifact.Description,
		Parts:       artifactParts,
	})
	if err != nil {
		return nil, FileReportOutput{}, fmt.Errorf("file_report: %w", err)
	}

	s.logger.Info("file_report standalone", "artifact_id", a.ID, "by", caller)
	return nil, FileReportOutput{
		ArtifactID: a.ID.String(),
		State:      "standalone",
		Completed:  false,
	}, nil
}

// --- acknowledge_directive ---

// AcknowledgeDirectiveInput is the input for the acknowledge_directive tool.
type AcknowledgeDirectiveInput struct {
	DirectiveID string `json:"directive_id" jsonschema:"required" jsonschema_description:"Task UUID of the directive to acknowledge"`
}

// AcknowledgeDirectiveOutput is the output of the acknowledge_directive tool.
type AcknowledgeDirectiveOutput struct {
	TaskID         string `json:"task_id"`
	AcknowledgedBy string `json:"acknowledged_by"`
	State          string `json:"state"`
}

func (s *Server) acknowledgeDirective(ctx context.Context, _ *mcp.CallToolRequest, input AcknowledgeDirectiveInput) (*mcp.CallToolResult, AcknowledgeDirectiveOutput, error) {
	taskID, err := uuid.Parse(input.DirectiveID)
	if err != nil {
		return nil, AcknowledgeDirectiveOutput{}, fmt.Errorf("acknowledge_directive: invalid directive_id: %w", err)
	}

	caller := agent.Name(s.callerIdentity(ctx))
	auth, err := agent.Authorize(ctx, s.registry, caller, agent.ActionAcceptTask)
	if err != nil {
		return nil, AcknowledgeDirectiveOutput{}, fmt.Errorf("acknowledge_directive: %w", err)
	}

	// Pre-flight: load the task so non-existent IDs and wrong-state /
	// wrong-target IDs return distinct errors. Without this lookup the
	// store's Accept SQL ('UPDATE … WHERE id=$1 AND state=submitted')
	// returns no rows for both 'no such task' and 'task already
	// accepted', which the store then maps to ErrConflict — leaving
	// callers staring at 'task: conflict' for an unparseable mix of
	// causes. The pre-flight cost is one extra SELECT only on the
	// happy path; failure paths get a clear message instead of a
	// generic state-machine error.
	existing, err := s.tasks.Task(ctx, taskID)
	if err != nil {
		if errors.Is(err, task.ErrNotFound) {
			return nil, AcknowledgeDirectiveOutput{}, fmt.Errorf("acknowledge_directive: task %s not found", taskID)
		}
		return nil, AcknowledgeDirectiveOutput{}, fmt.Errorf("acknowledge_directive: loading task: %w", err)
	}
	if existing.Target != string(caller) {
		return nil, AcknowledgeDirectiveOutput{}, fmt.Errorf("acknowledge_directive: caller %q is not the task target (%q); only the assignee can accept a directive", caller, existing.Target)
	}
	if existing.State != task.StateSubmitted {
		return nil, AcknowledgeDirectiveOutput{}, fmt.Errorf("acknowledge_directive: task %s is in state %q; acknowledge only works on tasks in 'submitted' state", taskID, existing.State)
	}

	var accepted *task.Task
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		accepted, err = s.tasks.WithTx(tx).Accept(ctx, auth, taskID)
		return err
	})
	if err != nil {
		return nil, AcknowledgeDirectiveOutput{}, fmt.Errorf("acknowledge_directive: %w", err)
	}

	s.logger.Info("acknowledge_directive", "task_id", taskID, "by", caller)
	return nil, AcknowledgeDirectiveOutput{
		TaskID:         accepted.ID.String(),
		AcknowledgedBy: string(caller),
		State:          string(accepted.State),
	}, nil
}

// --- task_detail ---

// TaskDetailInput is the input for the task_detail tool.
type TaskDetailInput struct {
	TaskID string `json:"task_id" jsonschema:"required" jsonschema_description:"UUID of the task to fetch"`
}

// TaskDetailOutput bundles the task row with its full message history
// and every artifact attached to it. Messages come back in submission
// order (position ASC). Artifacts are unordered — the artifact table has
// no user-meaningful ordering beyond creation time, which the schema
// does not guarantee is monotonic across concurrent writers.
type TaskDetailOutput struct {
	Task      task.Task           `json:"task"`
	Messages  []task.Message      `json:"messages"`
	Artifacts []artifact.Artifact `json:"artifacts"`
}

func (s *Server) taskDetail(ctx context.Context, _ *mcp.CallToolRequest, input TaskDetailInput) (*mcp.CallToolResult, TaskDetailOutput, error) {
	taskID, err := uuid.Parse(input.TaskID)
	if err != nil {
		return nil, TaskDetailOutput{}, fmt.Errorf("task_detail: invalid task_id: %w", err)
	}

	t, err := s.tasks.Task(ctx, taskID)
	if err != nil {
		// Treat both "not found" and "caller not a party" identically to
		// avoid leaking task existence across the coordination boundary.
		if errors.Is(err, task.ErrNotFound) {
			return nil, TaskDetailOutput{}, fmt.Errorf("task_detail: %w", task.ErrNotFound)
		}
		return nil, TaskDetailOutput{}, fmt.Errorf("task_detail: fetching task: %w", err)
	}

	// Authorization: caller must be the task source or target. Agent
	// notes belonging to the target remain private — this tool only
	// exposes the coordination surface (task / message / artifact),
	// never the target's self-directed narrative. Rejected-design
	// reasoning in docs/narrative-rewrite-scope.md §8.10.
	caller := s.callerIdentity(ctx)
	if caller != t.Source && caller != t.Target {
		return nil, TaskDetailOutput{}, fmt.Errorf("task_detail: %w", task.ErrNotFound)
	}

	messages, err := s.tasks.Messages(ctx, taskID)
	if err != nil {
		return nil, TaskDetailOutput{}, fmt.Errorf("task_detail: fetching messages: %w", err)
	}

	artifacts, err := s.artifacts.ForTask(ctx, taskID)
	if err != nil {
		return nil, TaskDetailOutput{}, fmt.Errorf("task_detail: fetching artifacts: %w", err)
	}

	s.logger.Info("task_detail", "task_id", taskID, "by", caller,
		"messages", len(messages), "artifacts", len(artifacts))

	return nil, TaskDetailOutput{
		Task:      *t,
		Messages:  messages,
		Artifacts: artifacts,
	}, nil
}
