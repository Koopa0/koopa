package mcp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/directive"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/insight"
	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/learnsession"
	"github.com/Koopa0/koopa0.dev/internal/project"
	"github.com/Koopa0/koopa0.dev/internal/report"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// Server is the MCP v2 server exposing workflow-driven tools.
type Server struct {
	server *mcp.Server

	// Phase 1 stores
	tasks    *task.Store
	journal  *journal.Store
	dayplan  *daily.Store
	contents *content.Store
	projects *project.Store

	// Phase 2 stores
	goals      *goal.Store
	directives *directive.Store
	reports    *report.Store
	insights   *insight.Store

	// Phase 3 stores
	learn *learnsession.Store

	// Configuration
	participant    string         // calling participant name (from env)
	loc            *time.Location // user timezone for day boundaries
	proposalSecret []byte         // HMAC key for proposal tokens
	logger         *slog.Logger

	// Telemetry
	recordToolCall func(context.Context, ToolCallRecord)
}

// ToolCallRecord holds telemetry data for a single tool invocation.
type ToolCallRecord struct {
	Name        string
	Duration    time.Duration
	IsError     bool
	IsEmpty     bool
	InputBytes  int
	OutputBytes int
}

// ServerOption configures optional Server dependencies.
type ServerOption func(*Server)

// WithParticipant sets the calling participant identity.
func WithParticipant(name string) ServerOption {
	return func(s *Server) { s.participant = name }
}

// WithLocation sets the user timezone for day boundary calculations.
func WithLocation(loc *time.Location) ServerOption {
	return func(s *Server) { s.loc = loc }
}

// WithTelemetry enables async tool call logging.
func WithTelemetry(recorder func(context.Context, ToolCallRecord)) ServerOption {
	return func(s *Server) { s.recordToolCall = recorder }
}

// NewServer creates an MCP v2 server with all registered tools.
func NewServer(
	tasks *task.Store,
	js *journal.Store,
	dayplan *daily.Store,
	contents *content.Store,
	projects *project.Store,
	goals *goal.Store,
	directives *directive.Store,
	reports *report.Store,
	insights *insight.Store,
	learn *learnsession.Store,
	logger *slog.Logger,
	opts ...ServerOption,
) *Server {
	s := &Server{
		tasks:       tasks,
		journal:     js,
		dayplan:     dayplan,
		contents:    contents,
		projects:    projects,
		goals:       goals,
		directives:  directives,
		reports:     reports,
		insights:    insights,
		learn:       learn,
		logger:      logger,
		participant: "human",
		loc:         time.UTC,
	}
	// Auto-generate proposal HMAC secret. Ephemeral — proposals don't survive restarts.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("mcp: failed to generate proposal secret: " + err.Error())
	}
	s.proposalSecret = secret

	for _, opt := range opts {
		opt(s)
	}

	s.server = mcp.NewServer(&mcp.Implementation{
		Name:    "koopa0-knowledge",
		Version: "v2.0.0",
	}, nil)

	// Tool annotation presets.
	f := false
	readOnly := &mcp.ToolAnnotations{
		ReadOnlyHint:  true,
		OpenWorldHint: &f,
	}
	additive := &mcp.ToolAnnotations{
		DestructiveHint: &f,
		OpenWorldHint:   &f,
	}
	additiveIdempotent := &mcp.ToolAnnotations{
		DestructiveHint: &f,
		IdempotentHint:  true,
		OpenWorldHint:   &f,
	}
	t := true
	destructive := &mcp.ToolAnnotations{
		DestructiveHint: &t,
		OpenWorldHint:   &f,
	}

	// --- Phase 1: Core Lifecycle ---

	addTool(s, &mcp.Tool{
		Name:        "morning_context",
		Description: "Get everything needed for daily planning: overdue tasks, today's tasks, committed daily plan items, upcoming tasks, and recent plan history. Use when the user starts their day.",
		Annotations: readOnly,
	}, s.morningContext)

	addTool(s, &mcp.Tool{
		Name:        "reflection_context",
		Description: "Get everything needed for evening reflection: plan vs actual completion, daily plan item outcomes, today's journal entries. Use for evening reflection or reviewing the day.",
		Annotations: readOnly,
	}, s.reflectionContext)

	addTool(s, &mcp.Tool{
		Name:        "search_knowledge",
		Description: "Search across all content types: articles, build logs, TILs, notes. Filters: content_type, project, date range. Use when looking for past knowledge or content.",
		Annotations: readOnly,
	}, s.searchKnowledge)

	addTool(s, &mcp.Tool{
		Name:        "capture_inbox",
		Description: "Quick task capture to inbox. Only title is required. Status is always inbox. Use when the user says 'add a task', 'remind me to', or expresses a concrete work item to capture.",
		Annotations: additive,
	}, s.captureInbox)

	addTool(s, &mcp.Tool{
		Name:        "advance_work",
		Description: "Task state transitions. Actions: clarify (inbox→todo with optional project/due/priority/energy), start (todo→in-progress), complete (→done, auto-updates daily plan item), defer (→someday). Use when the user wants to progress a task.",
		Annotations: destructive,
	}, s.advanceWork)

	addTool(s, &mcp.Tool{
		Name:        "plan_day",
		Description: "Set daily plan items for a date. Accepts task IDs with positions. Idempotent: re-planning replaces existing items. Use after morning_context when the user confirms their daily plan.",
		Annotations: additiveIdempotent,
	}, s.planDay)

	addTool(s, &mcp.Tool{
		Name:        "write_journal",
		Description: "Create a journal entry. Kind: plan (daily plan reasoning), context (session state snapshot), reflection (review), metrics (quantitative snapshot). Use for session logging and reflection.",
		Annotations: additive,
	}, s.writeJournal)

	// --- Phase 2: Intent & IPC ---

	addTool(s, &mcp.Tool{
		Name:        "propose_commitment",
		Description: "Propose creating a goal, project, milestone, directive, or insight. Returns a preview and signed proposal token. Does NOT write to the database. Use when the user wants to create a high-commitment entity — present the preview for approval before calling commit_proposal.",
		Annotations: readOnly,
	}, s.proposeCommitment)

	addTool(s, &mcp.Tool{
		Name:        "commit_proposal",
		Description: "Commit a previously proposed entity using the proposal_token from propose_commitment. Creates the entity in the database. Supports optional modifications to override fields before commit.",
		Annotations: additive,
	}, s.commitProposal)

	addTool(s, &mcp.Tool{
		Name:        "goal_progress",
		Description: "Show active goals with milestone progress (completed/total), area, quarter, and deadline. Use for goal reviews, weekly planning, or 'am I on track' questions.",
		Annotations: readOnly,
	}, s.goalProgress)

	addTool(s, &mcp.Tool{
		Name:        "file_report",
		Description: "Create a report. Optionally links to a directive via in_response_to. Source must be a participant with can_write_reports. Use when a participant needs to report output back to HQ or the directive issuer.",
		Annotations: additive,
	}, s.fileReport)

	addTool(s, &mcp.Tool{
		Name:        "acknowledge_directive",
		Description: "Mark a directive as acknowledged by the calling participant. Validates the caller is the target. Use when the AI picks up a directive during morning_context.",
		Annotations: additiveIdempotent,
	}, s.acknowledgeDirective)

	addTool(s, &mcp.Tool{
		Name:        "track_insight",
		Description: "Update an existing insight. Actions: verify (hypothesis confirmed), invalidate (hypothesis disproven), archive (retire), add_evidence (append supporting data). Insight creation goes through propose_commitment.",
		Annotations: additiveIdempotent,
	}, s.trackInsight)

	// --- Phase 3: Learning Domain ---

	addTool(s, &mcp.Tool{
		Name:        "start_session",
		Description: "Begin a learning session. Required: domain (e.g. leetcode, japanese), mode (retrieval/practice/mixed/review/reading). Validates no other active session exists. Use when the user wants to start a learning/practice session.",
		Annotations: additive,
	}, s.startSession)

	addTool(s, &mcp.Tool{
		Name:        "record_attempt",
		Description: "Record an attempt within the active learning session. Accepts semantic outcomes ('got it', 'needed help', 'gave up') mapped to schema enums by session mode. Auto-creates learning items and concepts. High-confidence observations are written directly; low-confidence returned as pending.",
		Annotations: additive,
	}, s.recordAttempt)

	addTool(s, &mcp.Tool{
		Name:        "end_session",
		Description: "End the active learning session. Optional reflection text creates a journal entry linked to the session. Returns session summary with all attempts.",
		Annotations: additive,
	}, s.endSession)

	addTool(s, &mcp.Tool{
		Name:        "learning_dashboard",
		Description: "Learning analytics: recent sessions, streaks, and activity. Views: overview (default), timeline. Filter by domain and lookback period.",
		Annotations: readOnly,
	}, s.learningDashboard)

	return s
}

// MCPServer returns the underlying mcp.Server for use with transports.
func (s *Server) MCPServer() *mcp.Server {
	return s.server
}

// today returns the current date in the user's timezone.
func (s *Server) today() time.Time {
	now := time.Now().In(s.loc)
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, s.loc)
}

// resolveProjectID resolves a project identifier (UUID, slug, alias, or title) to a project ID.
// Returns nil if resolution fails — capture proceeds without project context.
func (s *Server) resolveProjectID(ctx context.Context, input string) *uuid.UUID {
	if s.projects == nil {
		return nil
	}

	// Try UUID first.
	if id, err := uuid.Parse(input); err == nil {
		if _, pErr := s.projects.ProjectByID(ctx, id); pErr == nil {
			return &id
		}
	}

	// Try slug.
	if p, err := s.projects.ProjectBySlug(ctx, input); err == nil {
		return &p.ID
	}

	// Try alias.
	if p, err := s.projects.ProjectByAlias(ctx, input); err == nil {
		return &p.ID
	}

	// Try title (case-insensitive).
	if p, err := s.projects.ProjectByTitle(ctx, input); err == nil {
		return &p.ID
	}

	return nil
}

// toolResultError creates an error CallToolResult.
func toolResultError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}

// toolResultText creates a text CallToolResult.
func toolResultText(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// addTool registers a tool with optional telemetry wrapping.
// If tool.InputSchema is nil, addTool generates the schema with FlexInt support.
func addTool[I, O any](s *Server, tool *mcp.Tool, handler func(context.Context, *mcp.CallToolRequest, I) (*mcp.CallToolResult, O, error)) {
	if tool.InputSchema == nil {
		var zero I
		schema, err := jsonschema.ForType(reflect.TypeOf(zero), &jsonschema.ForOptions{
			TypeSchemas: flexTypeSchemas,
		})
		if err != nil {
			panic(fmt.Sprintf("mcp: schema generation failed for %s: %v", tool.Name, err))
		}
		tool.InputSchema = schema
	}

	s.server.AddTool(tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		var input I
		if err := json.Unmarshal(req.Params.Arguments, &input); err != nil {
			return toolResultError(fmt.Sprintf("invalid input: %v", err)), nil
		}

		override, output, err := handler(ctx, req, input)
		dur := time.Since(start)

		if err != nil {
			s.logToolCall(ctx, tool.Name, dur, 0, true, false)
			return toolResultError(err.Error()), nil
		}
		if override != nil {
			return override, nil
		}

		data, marshalErr := json.Marshal(output)
		if marshalErr != nil {
			s.logToolCall(ctx, tool.Name, dur, 0, true, false)
			return toolResultError(fmt.Sprintf("marshal output: %v", marshalErr)), nil
		}

		isEmpty := len(data) <= 4
		s.logToolCall(ctx, tool.Name, dur, len(data), false, isEmpty)
		return toolResultText(string(data)), nil
	})
}

// logToolCall records telemetry if configured.
func (s *Server) logToolCall(_ context.Context, name string, dur time.Duration, outBytes int, isErr, isEmpty bool) {
	if s.recordToolCall == nil {
		return
	}
	rec := ToolCallRecord{
		Name:        name,
		Duration:    dur,
		IsError:     isErr,
		IsEmpty:     isEmpty,
		OutputBytes: outBytes,
	}
	go func() { //nolint:gosec // G118: intentional — telemetry must outlive the request context
		tCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.recordToolCall(tCtx, rec)
	}()
}

// clamp constrains v to [lo, hi], returning def if v is 0.
func clamp(v, lo, hi, def int) int {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// reflectType is a helper for jsonschema type mapping.
var _ = reflect.TypeFor[FlexInt]
