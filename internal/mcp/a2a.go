// Copyright 2026 Koopa. All rights reserved.

// a2a.go holds the coordination-layer MCP tools that translate between
// a2a-go's Part shape and internal/agent/task. Five tool handlers live
// here:
//
//   - acknowledge_directive — target agent accepts an assigned task.
//   - file_report           — target agent completes a task with a
//     response message + artifact (atomic).
//   - task_detail           — read-side bundle (task + messages + artifacts).
//   - request_revision      — source agent moves a completed task back to
//     revision_requested with an optional response-message reason
//     (atomic with the transition).
//   - reaccept              — target agent picks up a revision-requested
//     task and moves it back to working.
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
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/agent/artifact"
	"github.com/Koopa0/koopa/internal/agent/task"
)

// partKeysHint is appended to every parseA2AParts error so the upstream
// a2a-go failure ("unknown part content type: [type concept ...]" lists
// the caller's bad keys, not the allowed ones) becomes actionable.
// See learning-studio brief REQ-1 + HERMES F-15 (2026-05-23).
const partKeysHint = `valid keys: text, raw, data, url (exactly one per part). For structured payloads use {"data":{...}} — top-level "type" and other unknown keys are silently ignored by a2a-go.`

// parseA2AParts deserializes a wire-side JSON array of a2a.Part values
// into typed Go values. This is the single entry point for wire→in-memory
// Part conversion across the MCP layer.
func parseA2AParts(raw []json.RawMessage) ([]*a2a.Part, error) {
	out := make([]*a2a.Part, 0, len(raw))
	for i, r := range raw {
		var p a2a.Part
		if err := json.Unmarshal(r, &p); err != nil {
			return nil, fmt.Errorf("parts[%d]: %w; %s", i, err, partKeysHint)
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
	Parts       []json.RawMessage `json:"parts" jsonschema:"required" jsonschema_description:"Artifact content as a2a Part objects. Each element MUST contain EXACTLY ONE of: text (string), raw (base64 string), data (any JSON value), url (string). Optional siblings: filename, mediaType, metadata. WARNING: top-level 'type' and other unknown keys are silently ignored by a2a-go — for structured payloads use {\"data\":{...}}, NOT {\"type\":\"observation\",\"text\":\"...\"} (that stores as plain Text with no error). Examples: [{\"text\":\"summary prose\"}], [{\"data\":{\"signal\":\"weakness\",\"concept\":\"binary-search\"}}], [{\"url\":\"https://...\",\"mediaType\":\"image/png\"}]."`
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
	ResponseParts []json.RawMessage        `json:"response_parts,omitempty" jsonschema_description:"Response message parts (required when in_response_to is set). Same a2a Part shape as artifact.parts — exactly one of text/raw/data/url per element."`
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
	TaskID string `json:"task_id" jsonschema:"required" jsonschema_description:"Task UUID of the directive to acknowledge"`
}

// AcknowledgeDirectiveOutput is the output of the acknowledge_directive tool.
type AcknowledgeDirectiveOutput struct {
	TaskID         string `json:"task_id"`
	AcknowledgedBy string `json:"acknowledged_by"`
	State          string `json:"state"`
}

func (s *Server) acknowledgeDirective(ctx context.Context, _ *mcp.CallToolRequest, input AcknowledgeDirectiveInput) (*mcp.CallToolResult, AcknowledgeDirectiveOutput, error) {
	taskID, err := uuid.Parse(input.TaskID)
	if err != nil {
		return nil, AcknowledgeDirectiveOutput{}, fmt.Errorf("acknowledge_directive: invalid task_id: %w", err)
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
	// never the target's self-directed narrative. Why agent_notes stay
	// private to their author: docs/backend-semantic-contract.md §2
	// (agent_note) + .claude/rules/mcp-decision-policy.md §14.
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

// --- list_my_tasks ---

// ListMyTasksInput is the input for the list_my_tasks tool. The caller is
// taken from the request identity (the `as` field), not a struct field.
type ListMyTasksInput struct {
	Limit int `json:"limit,omitempty" jsonschema_description:"Max tasks per direction (received/issued), 1-50, default 20"`
}

// ListMyTasksOutput is the caller's open-task queue, split into received
// (tasks assigned to the caller — the inbox) and issued (tasks the caller
// created — the outbox). The two lists are disjoint: tasks.created_by <>
// assignee is CHECK-enforced, so no task appears in both.
type ListMyTasksOutput struct {
	Received []task.Task `json:"received"`
	Issued   []task.Task `json:"issued"`
}

// listMyTasks returns the calling agent's open coordination tasks in both
// directions. It exists because the only prior ways to see one's queue were
// the heavy morning_context aggregate (and only learning-studio had a
// per-agent default that scoped it) or task_detail, which needs a known id
// and cannot enumerate. Open states are submitted, working, and
// revision_requested (see task.Store.OpenForAssignee / OpenForCreator).
func (s *Server) listMyTasks(ctx context.Context, _ *mcp.CallToolRequest, input ListMyTasksInput) (*mcp.CallToolResult, ListMyTasksOutput, error) {
	caller := s.callerIdentity(ctx)
	limit := int32(clamp(input.Limit, 1, 50, 20))

	received, err := s.tasks.OpenForAssignee(ctx, caller, limit)
	if err != nil {
		return nil, ListMyTasksOutput{}, fmt.Errorf("list_my_tasks: received: %w", err)
	}
	issued, err := s.tasks.OpenForCreator(ctx, caller, limit)
	if err != nil {
		return nil, ListMyTasksOutput{}, fmt.Errorf("list_my_tasks: issued: %w", err)
	}

	s.logger.Info("list_my_tasks", "by", caller, "received", len(received), "issued", len(issued))
	return nil, ListMyTasksOutput{Received: received, Issued: issued}, nil
}

// --- request_revision ---

// RequestRevisionInput is the input for the request_revision tool.
//
// Caller identity is resolved via callerIdentity(ctx) (the "as" field
// or server default). The caller must be the task's source AND hold the
// SubmitTasks capability — capability gates at the type system level,
// the source-bound check runs in the handler.
type RequestRevisionInput struct {
	TaskID string  `json:"task_id" jsonschema:"required" jsonschema_description:"Task UUID of the completed directive to send back for revision"`
	Reason *string `json:"reason,omitempty" jsonschema_description:"Optional explanation. When non-empty after trimming, appended as a response message in the same transaction as the state transition — if the transition fails, the reason is rolled back."`
}

// RequestRevisionOutput is the output of the request_revision tool.
//
// ReasonAppended reports whether the optional reason was persisted; it
// is false when the caller omitted reason or supplied only whitespace,
// so the caller can distinguish "no reason provided" from "reason was
// silently dropped".
type RequestRevisionOutput struct {
	TaskID         string `json:"task_id"`
	RequestedBy    string `json:"requested_by"`
	State          string `json:"state"`
	ReasonAppended bool   `json:"reason_appended"`
}

func (s *Server) requestRevision(ctx context.Context, _ *mcp.CallToolRequest, input RequestRevisionInput) (*mcp.CallToolResult, RequestRevisionOutput, error) {
	taskID, err := uuid.Parse(input.TaskID)
	if err != nil {
		return nil, RequestRevisionOutput{}, fmt.Errorf("request_revision: invalid task_id: %w", err)
	}

	caller := agent.Name(s.callerIdentity(ctx))
	auth, err := agent.Authorize(ctx, s.registry, caller, agent.ActionRequestRevision)
	if err != nil {
		return nil, RequestRevisionOutput{}, fmt.Errorf("request_revision: %w", err)
	}

	// Pre-flight load: distinct errors for not-found, wrong source, wrong
	// state. Without it, the SQL UPDATE narrowing on state='completed' would
	// collapse all three into a generic ErrConflict. Mirrors the
	// acknowledge_directive / file_report preflight pattern.
	existing, err := s.tasks.Task(ctx, taskID)
	if err != nil {
		if errors.Is(err, task.ErrNotFound) {
			return nil, RequestRevisionOutput{}, fmt.Errorf("request_revision: task %s not found", taskID)
		}
		return nil, RequestRevisionOutput{}, fmt.Errorf("request_revision: loading task: %w", err)
	}
	if existing.Source != string(caller) {
		return nil, RequestRevisionOutput{}, fmt.Errorf("request_revision: caller %q is not the task source (%q); only the source can request a revision", caller, existing.Source)
	}
	if existing.State != task.StateCompleted {
		return nil, RequestRevisionOutput{}, fmt.Errorf("request_revision: task %s is in state %q; request_revision only works on tasks in 'completed' state", taskID, existing.State)
	}

	// Atomicity contract: reason append (if any) and the state transition
	// run in the same actor-bound transaction. A failed transition rolls
	// back the message, so callers cannot leave an orphaned reason on a
	// task that didn't actually transition.
	var (
		revised        *task.Task
		reasonAppended bool
	)
	trimmedReason := ""
	if input.Reason != nil {
		trimmedReason = strings.TrimSpace(*input.Reason)
	}

	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		store := s.tasks.WithTx(tx)
		if trimmedReason != "" {
			if _, err := store.AppendMessage(ctx, taskID, task.RoleResponse, []*a2a.Part{a2a.NewTextPart(trimmedReason)}); err != nil {
				return err
			}
			reasonAppended = true
		}
		t, err := store.RequestRevision(ctx, auth, taskID)
		if err != nil {
			return err
		}
		revised = t
		return nil
	})
	if err != nil {
		return nil, RequestRevisionOutput{}, fmt.Errorf("request_revision: %w", err)
	}

	s.logger.Info("request_revision", "task_id", taskID, "by", caller, "reason_appended", reasonAppended)
	return nil, RequestRevisionOutput{
		TaskID:         revised.ID.String(),
		RequestedBy:    string(caller),
		State:          string(revised.State),
		ReasonAppended: reasonAppended,
	}, nil
}

// --- reaccept ---

// ReacceptInput is the input for the reaccept tool.
//
// Caller identity is resolved via callerIdentity(ctx). The caller must
// be the task's target AND hold ReceiveTasks; capability gates at the
// type system, the target-bound check runs in the handler.
type ReacceptInput struct {
	TaskID string `json:"task_id" jsonschema:"required" jsonschema_description:"Task UUID of the revision_requested directive to pick back up"`
}

// ReacceptOutput is the output of the reaccept tool.
type ReacceptOutput struct {
	TaskID       string `json:"task_id"`
	ReacceptedBy string `json:"reaccepted_by"`
	State        string `json:"state"`
}

func (s *Server) reaccept(ctx context.Context, _ *mcp.CallToolRequest, input ReacceptInput) (*mcp.CallToolResult, ReacceptOutput, error) {
	taskID, err := uuid.Parse(input.TaskID)
	if err != nil {
		return nil, ReacceptOutput{}, fmt.Errorf("reaccept: invalid task_id: %w", err)
	}

	caller := agent.Name(s.callerIdentity(ctx))
	auth, err := agent.Authorize(ctx, s.registry, caller, agent.ActionReacceptTask)
	if err != nil {
		return nil, ReacceptOutput{}, fmt.Errorf("reaccept: %w", err)
	}

	existing, err := s.tasks.Task(ctx, taskID)
	if err != nil {
		if errors.Is(err, task.ErrNotFound) {
			return nil, ReacceptOutput{}, fmt.Errorf("reaccept: task %s not found", taskID)
		}
		return nil, ReacceptOutput{}, fmt.Errorf("reaccept: loading task: %w", err)
	}
	if existing.Target != string(caller) {
		return nil, ReacceptOutput{}, fmt.Errorf("reaccept: caller %q is not the task target (%q); only the assignee can reaccept a revision", caller, existing.Target)
	}
	if existing.State != task.StateRevisionRequested {
		return nil, ReacceptOutput{}, fmt.Errorf("reaccept: task %s is in state %q; reaccept only works on tasks in 'revision_requested' state", taskID, existing.State)
	}

	var reaccepted *task.Task
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		t, err := s.tasks.WithTx(tx).Reaccept(ctx, auth, taskID)
		if err != nil {
			return err
		}
		reaccepted = t
		return nil
	})
	if err != nil {
		return nil, ReacceptOutput{}, fmt.Errorf("reaccept: %w", err)
	}

	s.logger.Info("reaccept", "task_id", taskID, "by", caller)
	return nil, ReacceptOutput{
		TaskID:       reaccepted.ID.String(),
		ReacceptedBy: string(caller),
		State:        string(reaccepted.State),
	}, nil
}
