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

	"github.com/Koopa0/koopa0.dev/internal/agent"
	agentnote "github.com/Koopa0/koopa0.dev/internal/agent/note"
	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/feed"
	"github.com/Koopa0/koopa0.dev/internal/feed/entry"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/hypothesis"
	"github.com/Koopa0/koopa0.dev/internal/learning"
	"github.com/Koopa0/koopa0.dev/internal/mcp/ops"
	"github.com/Koopa0/koopa0.dev/internal/obsidian/note"
	"github.com/Koopa0/koopa0.dev/internal/plan"
	"github.com/Koopa0/koopa0.dev/internal/project"
	"github.com/Koopa0/koopa0.dev/internal/stats"
	"github.com/Koopa0/koopa0.dev/internal/todo"
)

// Server is the MCP v2 server exposing workflow-driven tools.
type Server struct {
	server *mcp.Server

	// Phase 1 stores
	todos      *todo.Store
	agentNotes *agentnote.Store
	dayplan    *daily.Store
	contents   *content.Store
	projects   *project.Store
	notes      *note.Store

	// Phase 2 stores
	goals      *goal.Store
	hypotheses *hypothesis.Store
	// TODO(coordination-rebuild): add *task.Store, *message.Store, *artifact.Store
	// once the coordination packages exist. The propose_commitment(directive),
	// acknowledge_directive, and file_report handlers currently return
	// ErrNotImplemented placeholders — they'll dispatch through these stores
	// in the follow-up PR.

	// Agent registry — source of truth for capability enforcement via
	// agent.Authorize. Wired in from cmd/app/main.go so the CLI and tests
	// can inject custom rosters when needed.
	registry *agent.Registry

	// Phase 3 stores
	learn *learning.Store
	plans *plan.Store

	// Phase 4 stores (optional)
	feeds       *feed.Store
	feedEntries *entry.Store
	stats       *stats.Store

	// Database pool for cross-store transactions
	pool *pgxpool.Pool

	// Configuration
	participant    string         // calling participant name (from env)
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

// WithRegistry injects a pre-built agent registry. Required in production
// because callers of mutation tools must be resolved against it; optional in
// tests that use the default BuiltinAgents.
func WithRegistry(r *agent.Registry) ServerOption {
	return func(s *Server) { s.registry = r }
}

// NewServer creates an MCP v2 server. All stores are created from the pool.
func NewServer(pool *pgxpool.Pool, logger *slog.Logger, opts ...ServerOption) *Server {
	s := &Server{
		todos:       todo.NewStore(pool),
		agentNotes:  agentnote.NewStore(pool),
		dayplan:     daily.NewStore(pool),
		contents:    content.NewStore(pool),
		projects:    project.NewStore(pool),
		notes:       note.NewStore(pool),
		goals:       goal.NewStore(pool),
		hypotheses:  hypothesis.NewStore(pool),
		registry:    agent.NewBuiltinRegistry(),
		learn:       learning.NewStore(pool),
		plans:       plan.NewStore(pool),
		feedEntries: entry.NewStore(pool),
		feeds:       feed.NewStore(pool, logger),
		stats:       stats.NewStore(pool),
		pool:        pool,
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

	// Tool metadata (name, description, annotations) is declared in the
	// internal/mcp/ops catalog. Handler method references stay here, since
	// each has distinct generic I/O types that cannot share a registration
	// loop. A drift test in ops_test.go asserts catalog ↔ registration parity.

	// --- Phase 1: Core Lifecycle ---
	addTool(s, toolFrom(ops.MorningContext), s.morningContext)
	addTool(s, toolFrom(ops.ReflectionContext), s.reflectionContext)
	addTool(s, toolFrom(ops.SearchKnowledge), s.searchKnowledge)
	addTool(s, toolFrom(ops.CaptureInbox), s.captureInbox)
	addTool(s, toolFrom(ops.AdvanceWork), s.advanceWork)
	addTool(s, toolFrom(ops.PlanDay), s.planDay)
	addTool(s, toolFrom(ops.WriteJournal), s.writeJournal)

	// --- Phase 2: Intent & IPC ---
	addTool(s, toolFrom(ops.ProposeCommitment), s.proposeCommitment)
	addTool(s, toolFrom(ops.CommitProposal), s.commitProposal)
	addTool(s, toolFrom(ops.GoalProgress), s.goalProgress)
	addTool(s, toolFrom(ops.FileReport), s.fileReport)
	addTool(s, toolFrom(ops.AcknowledgeDirective), s.acknowledgeDirective)
	addTool(s, toolFrom(ops.TrackInsight), s.trackInsight)

	// --- Phase 3: Learning Domain ---
	addTool(s, toolFrom(ops.StartSession), s.startSession)
	addTool(s, toolFrom(ops.RecordAttempt), s.recordAttempt)
	addTool(s, toolFrom(ops.EndSession), s.endSession)
	addTool(s, toolFrom(ops.LearningDashboard), s.learningDashboard)
	addTool(s, toolFrom(ops.AttemptHistory), s.attemptHistory)
	addTool(s, toolFrom(ops.ManagePlan), s.managePlan)

	// --- Phase 4: Content & Feeds ---
	addTool(s, toolFrom(ops.ManageContent), s.manageContent)
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

// callerIdentity returns the participant name for the current call.
// Checks context first (set by "as" field in tool input), falls back to server default.
func (s *Server) callerIdentity(ctx context.Context) string {
	if v, ok := ctx.Value(callerKey{}).(string); ok && v != "" {
		return v
	}
	return s.participant
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
		tool.InputSchema = schema
	}

	s.registeredNames = append(s.registeredNames, tool.Name)

	s.server.AddTool(tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()

		// Extract optional "as" field for per-call participant override.
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
		Description: "Caller participant identity (e.g. hq, content-studio). Set by project instructions.",
	}
	// Allow the "as" field to pass through — jsonschema-go sets
	// additionalProperties:false by default which would reject it.
	s.AdditionalProperties = nil
}

// reflectType is a helper for jsonschema type mapping.
var _ = reflect.TypeFor[FlexInt]
