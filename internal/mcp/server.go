package mcp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/agent/artifact"
	agentnote "github.com/Koopa0/koopa/internal/agent/note"
	"github.com/Koopa0/koopa/internal/agent/task"
	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/embedder"
	"github.com/Koopa0/koopa/internal/feed"
	"github.com/Koopa0/koopa/internal/feed/entry"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/learning/fsrs"
	"github.com/Koopa0/koopa/internal/learning/hypothesis"
	"github.com/Koopa0/koopa/internal/learning/plan"
	"github.com/Koopa0/koopa/internal/mcp/ops"
	"github.com/Koopa0/koopa/internal/note"
	"github.com/Koopa0/koopa/internal/project"
	"github.com/Koopa0/koopa/internal/stats"
	"github.com/Koopa0/koopa/internal/todo"
)

// Server is the MCP v2 server exposing workflow-driven tools.
type Server struct {
	server *mcp.Server

	// GTD and daily workflow
	todos      *todo.Store
	agentNotes *agentnote.Store
	dayplan    *daily.Store
	contents   *content.Store
	notes      *note.Store
	projects   *project.Store

	// Goals and hypotheses
	goals      *goal.Store
	hypotheses *hypothesis.Store

	// Agent coordination
	tasks     *task.Store
	artifacts *artifact.Store

	// Agent registry — source of truth for capability enforcement via
	// agent.Authorize. Wired in from cmd/app/main.go so the CLI and tests
	// can inject custom rosters when needed.
	registry *agent.Registry

	// Learning domain
	learn *learning.Store
	plans *plan.Store
	fsrs  *fsrs.Store

	// Content and feeds
	feeds       *feed.Store
	feedEntries *entry.Store
	stats       *stats.Store

	// Embedder for search_knowledge semantic branch. Nullable — when nil,
	// search_knowledge runs FTS-only. Populated from cmd/app/main.go when
	// GEMINI_API_KEY is set.
	embedder *embedder.Embedder

	// Database pool for cross-store transactions
	pool *pgxpool.Pool

	// Configuration
	callerAgent    string         // calling agent name (from env)
	loc            *time.Location // user timezone for day boundaries
	proposalSecret []byte         // HMAC key for proposal tokens
	logger         *slog.Logger

	// Telemetry
	recordToolCall func(context.Context, ToolCallRecord)

	// registeredNames records every tool name passed through addTool,
	// in registration order. It is populated exclusively during NewServer
	// and read only by TestOpsCatalogDrift, which asserts the sequence
	// matches ops.All(). The field is not safe to mutate after startup
	// and exists for drift detection, not runtime introspection.
	registeredNames []string
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

// WithCallerAgent sets the calling agent identity.
func WithCallerAgent(name string) ServerOption {
	return func(s *Server) { s.callerAgent = name }
}

// WithLocation sets the user timezone for day boundary calculations.
func WithLocation(loc *time.Location) ServerOption {
	return func(s *Server) { s.loc = loc }
}

// WithTelemetry enables async tool call logging.
func WithTelemetry(recorder func(context.Context, ToolCallRecord)) ServerOption {
	return func(s *Server) { s.recordToolCall = recorder }
}

// WithRegistry injects a pre-built agent registry. Required in production
// because callers of mutation tools must be resolved against it; optional in
// tests that use the default BuiltinAgents.
func WithRegistry(r *agent.Registry) ServerOption {
	return func(s *Server) { s.registry = r }
}

// WithEmbedder enables the semantic branch of search_knowledge. When unset
// (or set to nil) the tool falls back to FTS-only — that path remains
// functional in every deployment, so embedder wiring is deliberately
// optional rather than required.
func WithEmbedder(e *embedder.Embedder) ServerOption {
	return func(s *Server) { s.embedder = e }
}

// NewServer creates an MCP v2 server. All stores are created from the pool.
func NewServer(pool *pgxpool.Pool, logger *slog.Logger, opts ...ServerOption) *Server {
	artStore := artifact.NewStore(pool)
	s := &Server{
		todos:       todo.NewStore(pool),
		agentNotes:  agentnote.NewStore(pool),
		dayplan:     daily.NewStore(pool),
		contents:    content.NewStore(pool),
		notes:       note.NewStore(pool),
		projects:    project.NewStore(pool),
		goals:       goal.NewStore(pool),
		hypotheses:  hypothesis.NewStore(pool),
		tasks:       task.NewStore(pool, artStore),
		artifacts:   artStore,
		registry:    agent.NewBuiltinRegistry(),
		learn:       learning.NewStore(pool),
		plans:       plan.NewStore(pool),
		fsrs:        fsrs.NewStore(pool),
		feedEntries: entry.NewStore(pool),
		feeds:       feed.NewStore(pool, logger),
		stats:       stats.NewStore(pool),
		pool:        pool,
		logger:      logger,
		callerAgent: "human",
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

	// Tool metadata (name, description, annotations) is declared in the
	// internal/mcp/ops catalog. Handler method references stay here, since
	// each has distinct generic I/O types that cannot share a registration
	// loop. A drift test in ops_test.go asserts catalog ↔ registration parity.

	// --- Core Lifecycle ---
	addTool(s, toolFrom(ops.MorningContext), s.morningContext)
	addTool(s, toolFrom(ops.ReflectionContext), s.reflectionContext)
	addTool(s, toolFrom(ops.SearchKnowledge), s.searchKnowledge)
	addTool(s, toolFrom(ops.CaptureInbox), s.captureInbox)
	addTool(s, toolFrom(ops.AdvanceWork), s.advanceWork)
	addTool(s, toolFrom(ops.PlanDay), s.planDay)
	addTool(s, toolFrom(ops.WriteAgentNote), s.writeAgentNote)
	addTool(s, toolFrom(ops.QueryAgentNotes), s.queryAgentNotes)

	// --- Intent & a2a ---
	addTool(s, toolFrom(ops.ProposeCommitment), s.proposeCommitment)
	addTool(s, toolFrom(ops.CommitProposal), s.commitProposal)
	addTool(s, toolFrom(ops.GoalProgress), s.goalProgress)
	addTool(s, toolFrom(ops.FileReport), s.fileReport)
	addTool(s, toolFrom(ops.AcknowledgeDirective), s.acknowledgeDirective)
	addTool(s, toolFrom(ops.TaskDetail), s.taskDetail)
	addTool(s, toolFrom(ops.TrackHypothesis), s.trackHypothesis)

	// --- Learning Domain ---
	addTool(s, toolFrom(ops.StartSession), s.startSession)
	addTool(s, toolFrom(ops.RecordAttempt), s.recordAttempt)
	addTool(s, toolFrom(ops.EndSession), s.endSession)
	addTool(s, toolFrom(ops.LearningDashboard), s.learningDashboard)
	addTool(s, toolFrom(ops.RecommendNextTarget), s.recommendNextTarget)
	addTool(s, toolFrom(ops.AttemptHistory), s.attemptHistory)
	addTool(s, toolFrom(ops.ManagePlan), s.managePlan)
	addTool(s, toolFrom(ops.SessionProgress), s.sessionProgress)

	// --- Content lifecycle (flat tools) ---
	addTool(s, toolFrom(ops.CreateContent), s.createContentTool)
	addTool(s, toolFrom(ops.UpdateContent), s.updateContentTool)
	addTool(s, toolFrom(ops.SubmitContentForReview), s.submitContentForReviewTool)
	addTool(s, toolFrom(ops.RevertContentToDraft), s.revertContentToDraftTool)
	addTool(s, toolFrom(ops.PublishContent), s.publishContentTool)
	addTool(s, toolFrom(ops.ArchiveContent), s.archiveContentTool)
	addTool(s, toolFrom(ops.ListContent), s.listContentTool)
	addTool(s, toolFrom(ops.ReadContent), s.readContentTool)

	// --- Notes (flat tools) ---
	addTool(s, toolFrom(ops.CreateNote), s.createNote)
	addTool(s, toolFrom(ops.UpdateNote), s.updateNote)
	addTool(s, toolFrom(ops.UpdateNoteMaturity), s.updateNoteMaturity)

	// --- Feeds & system ---
	addTool(s, toolFrom(ops.ManageFeeds), s.manageFeeds)
	addTool(s, toolFrom(ops.SystemStatus), s.systemStatus)

	// --- Extra: Cross-session & Aggregation ---
	addTool(s, toolFrom(ops.SessionDelta), s.sessionDelta)
	addTool(s, toolFrom(ops.WeeklySummary), s.weeklySummary)

	return s
}

// toolFrom converts an ops.Meta accessor into an MCP tool descriptor.
// The accessor is invoked once at registration time; callers pass the
// function value rather than a struct pointer so the catalog can stay
// mutation-free without forcing every call site to take an address.
func toolFrom(metaFn func() ops.Meta) *mcp.Tool {
	m := metaFn()
	return &mcp.Tool{
		Name:        m.Name,
		Description: m.Description,
		Annotations: annotationsFor(m.Writability),
	}
}

// annotationsFor maps a Writability label to MCP tool annotations.
// OpenWorldHint is always false for koopa tools: all effects are local
// to the koopa database, none call unbounded external services.
//
// An unknown Writability is a programming error (a typo or a new label
// that forgot to update this switch) and panics at NewServer time —
// before any handler can run — so the failure surfaces immediately
// instead of hiding inside a response with missing hints.
func annotationsFor(w ops.Writability) *mcp.ToolAnnotations {
	closed := false
	switch w {
	case ops.ReadOnly:
		return &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: &closed,
		}
	case ops.Additive:
		return &mcp.ToolAnnotations{
			DestructiveHint: &closed,
			OpenWorldHint:   &closed,
		}
	case ops.Idempotent:
		return &mcp.ToolAnnotations{
			DestructiveHint: &closed,
			IdempotentHint:  true,
			OpenWorldHint:   &closed,
		}
	case ops.Destructive:
		destructive := true
		return &mcp.ToolAnnotations{
			DestructiveHint: &destructive,
			OpenWorldHint:   &closed,
		}
	default:
		panic("mcp: unknown ops.Writability: " + string(w))
	}
}

// Run starts the MCP server with the given transport and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context, transport mcp.Transport) error {
	return s.server.Run(ctx, transport)
}

// HTTPHandler returns an http.Handler for Streamable HTTP transport.
func (s *Server) HTTPHandler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return s.server
	}, nil)
}

// callerIdentity returns the agent name for the current call.
// Checks context first (set by "as" field in tool input), falls back to server default.
func (s *Server) callerIdentity(ctx context.Context) string {
	if v, ok := ctx.Value(callerKey{}).(string); ok && v != "" {
		return v
	}
	return s.callerAgent
}

// ExplicitCallerIdentity reports whether the caller supplied an explicit `as`
// field on the MCP request and returns the resolved identity. Returns
// (false, "") when the caller omitted `as` and fell through to the server
// default (s.callerAgent). Handlers that gate on identity (e.g.
// publish_content, which is human-only) MUST use this — callerIdentity
// alone cannot distinguish "explicitly identified as human" from "server
// default happened to be 'human'".
func (s *Server) ExplicitCallerIdentity(ctx context.Context) (explicit bool, name string) {
	if v, ok := ctx.Value(callerKey{}).(string); ok && v != "" {
		return true, v
	}
	return false, ""
}

type callerKey struct{}

// extractCallerIdentity checks for an "as" field in the raw arguments
// and stores it in context. This lets each Cowork project self-identify
// without server-level configuration.
func (s *Server) extractCallerIdentity(ctx context.Context, args json.RawMessage) context.Context {
	var peek struct {
		As string `json:"as"`
	}
	if json.Unmarshal(args, &peek) == nil && peek.As != "" {
		return context.WithValue(ctx, callerKey{}, peek.As)
	}
	return ctx
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
// Array fields in the schema are post-processed to remove nullable type
// (Go slices generate ["null","array"] but MCP clients may stringify nullable arrays).
// Enum values declared on ops.Meta.FieldEnums are injected into matching
// top-level properties so `tools/list` advertises valid values structurally
// without forcing clients to parse Description prose.
func addTool[I, O any](s *Server, tool *mcp.Tool, handler func(context.Context, *mcp.CallToolRequest, I) (*mcp.CallToolResult, O, error)) {
	if tool.InputSchema == nil {
		var zero I
		schema, err := jsonschema.ForType(reflect.TypeOf(zero), &jsonschema.ForOptions{
			TypeSchemas: flexTypeSchemas,
		})
		if err != nil {
			panic(fmt.Sprintf("mcp: schema generation failed for %s: %v", tool.Name, err))
		}
		fixNullableArrays(schema)
		injectCallerIdentityField(schema)
		injectFieldEnums(schema, tool.Name)
		tool.InputSchema = schema
	}

	s.registeredNames = append(s.registeredNames, tool.Name)

	s.server.AddTool(tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()

		// Extract optional "as" field for per-call agent override.
		// Project instructions tell each AI: "在所有 tool call 中傳入 as: 'hq'"
		ctx = s.extractCallerIdentity(ctx, req.Params.Arguments)

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

// fixNullableArrays walks a schema and converts ["null","array"] to "array"
// for all properties. Go slices generate nullable types, but MCP clients
// (Claude Desktop) may stringify nullable arrays. Making them non-nullable
// ensures clients send actual JSON arrays.
func fixNullableArrays(s *jsonschema.Schema) {
	for _, prop := range s.Properties {
		if prop == nil {
			continue
		}
		// Convert ["null","array"] → "array"
		if len(prop.Types) == 2 && slices.Contains(prop.Types, "null") && slices.Contains(prop.Types, "array") {
			prop.Types = nil
			prop.Type = "array"
		}
		// Recurse into object properties
		if len(prop.Properties) > 0 {
			fixNullableArrays(prop)
		}
	}
}

// injectFieldEnums applies ops.Meta.FieldEnums to the generated schema —
// for each (field, values) pair whose field matches a top-level property,
// set that property's .Enum slice. Looked up by tool name against
// ops.All() so addTool stays agnostic about the specific catalog shape.
// Absent meta or empty FieldEnums is a no-op.
func injectFieldEnums(schema *jsonschema.Schema, toolName string) {
	var meta *ops.Meta
	for i, m := range ops.All() {
		if m.Name == toolName {
			meta = &ops.All()[i]
			break
		}
	}
	if meta == nil || len(meta.FieldEnums) == 0 || schema.Properties == nil {
		return
	}
	for field, values := range meta.FieldEnums {
		prop, ok := schema.Properties[field]
		if !ok || prop == nil {
			continue
		}
		enumAny := make([]any, len(values))
		for i, v := range values {
			enumAny[i] = v
		}
		prop.Enum = enumAny
	}
}

// injectCallerIdentityField adds the "as" property to a tool schema and
// removes additionalProperties:false so the MCP client can pass it.
// This enables caller self-identification: each Cowork project's instructions
// tell the AI to pass as:"hq" (or "content-studio", etc.) in every tool call.
func injectCallerIdentityField(s *jsonschema.Schema) {
	if s.Properties == nil {
		s.Properties = map[string]*jsonschema.Schema{}
	}
	s.Properties["as"] = &jsonschema.Schema{
		Type:        "string",
		Description: "Caller agent identity (e.g. hq, content-studio). Set by project instructions.",
	}
	// Allow the "as" field to pass through — jsonschema-go sets
	// additionalProperties:false by default which would reject it.
	s.AdditionalProperties = nil
}

// reflectType is a helper for jsonschema type mapping.
var _ = reflect.TypeFor[FlexInt]
