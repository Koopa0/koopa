// Command mcp runs a Model Context Protocol server, exposing read-only tools
// for querying the koopa0.dev knowledge engine.
//
// Transport is selected by the MCP_TRANSPORT env var:
//   - "http" (default): Streamable HTTP on MCP_PORT (default 8081), requires MCP_TOKEN
//   - "stdio": stdio transport for local Claude Code usage
//
// Usage:
//
//	DATABASE_URL=postgres://... MCP_TOKEN=secret go run ./cmd/mcp
//	DATABASE_URL=postgres://... MCP_TRANSPORT=stdio go run ./cmd/mcp
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	pgvector "github.com/pgvector/pgvector-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/feed/entry"
	"github.com/koopa0/blog-backend/internal/goal"
	mcpkg "github.com/koopa0/blog-backend/internal/mcp"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/notion"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/session"
	"github.com/koopa0/blog-backend/internal/stats"
	"github.com/koopa0/blog-backend/internal/task"
)

func main() {
	// MCP stdio uses stdout — always log to stderr.
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := loadConfig(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, cfg, logger)
	stop()
	if err != nil {
		logger.Error("MCP server stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config, logger *slog.Logger) error {
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("parsing DATABASE_URL: %w", err)
	}
	poolCfg.MaxConns = 5

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}

	contentStore := content.NewStore(pool)
	taskStore := task.NewStore(pool)

	notionStore := notion.NewStore(pool)
	projectStore := project.NewStore(pool)
	goalStore := goal.NewStore(pool)
	collectedStore := entry.NewStore(pool)
	activityStore := activity.NewStore(pool)
	sessionStore := session.NewStore(pool)
	feedStore := feed.NewStore(pool, logger)

	var opts []mcpkg.ServerOption
	if cfg.NotionAPIKey != "" {
		logger.Info("notion write tools enabled")
		opts = append(opts, mcpkg.WithNotionTaskWriter(
			notionAdapter{client: notion.NewClient(cfg.NotionAPIKey)},
			notionStore,
		))
	} else {
		logger.Warn("NOTION_API_KEY not set — create_task and complete_task will be unavailable")
	}
	taipeiLoc, locErr := time.LoadLocation("Asia/Taipei")
	if locErr != nil {
		return fmt.Errorf("loading Asia/Taipei timezone: %w", locErr)
	}
	statsStore := stats.NewStore(pool)
	opts = append(opts,
		mcpkg.WithLocation(taipeiLoc),
		mcpkg.WithGoalWriter(goalStore),
		mcpkg.WithProjectWriter(projectStore),
		mcpkg.WithActivityWriter(activityStore),
		mcpkg.WithFeedStore(feedStore),
		mcpkg.WithSystemStatus(statsStore),
	)

	// Pipeline trigger via admin API (self-signs JWT using shared secret)
	if cfg.AdminAPIURL != "" {
		if cfg.JWTSecret == "" || cfg.AdminEmail == "" {
			logger.Error("ADMIN_API_URL set but JWT_SECRET or ADMIN_EMAIL missing — trigger_pipeline disabled")
		} else {
			opts = append(opts,
				mcpkg.WithPipelineTrigger(
					&httpPipelineTrigger{
						baseURL:    cfg.AdminAPIURL,
						jwtSecret:  []byte(cfg.JWTSecret),
						adminEmail: cfg.AdminEmail,
						logger:     logger,
					},
				),
			)
			logger.Info("pipeline trigger enabled", "admin_url", cfg.AdminAPIURL)
		}
	} else {
		logger.Warn("ADMIN_API_URL not set — trigger_pipeline will be unavailable")
	}

	// Optional O'Reilly content search (requires ORM_JWT)
	if cfg.ORMJWT != "" {
		opts = append(opts, mcpkg.WithOReilly(mcpkg.NewOReillyClient(cfg.ORMJWT)))
		logger.Info("O'Reilly content search enabled")
	} else {
		logger.Warn("ORM_JWT not set — search_oreilly_content will be unavailable")
	}

	// Tool call telemetry — async insert with timeout context, no impact on response time.
	opts = append(opts, mcpkg.WithTelemetry(func(ctx context.Context, rec mcpkg.ToolCallRecord) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("telemetry panic", "tool", rec.Name, "recover", r)
			}
		}()
		_, execErr := pool.Exec(ctx,
			"INSERT INTO tool_call_logs (tool_name, called_at, duration_ms, is_error, is_empty, input_bytes, output_bytes) VALUES ($1, now(), $2, $3, $4, $5, $6)",
			rec.Name, rec.Duration.Milliseconds(), rec.IsError, rec.IsEmpty, rec.InputBytes, rec.OutputBytes)
		if execErr != nil {
			logger.Warn("telemetry insert failed", "tool", rec.Name, "error", execErr)
		}
	}))

	// Optional semantic search (requires GEMINI_API_KEY)
	noteStore := note.NewStore(pool)
	if cfg.GeminiAPIKey != "" {
		qe, embedErr := newGeminiQueryEmbedder(ctx, logger)
		if embedErr != nil {
			logger.Warn("semantic search unavailable", "error", embedErr)
		} else {
			opts = append(opts, mcpkg.WithSemanticSearch(noteStore, qe))
			logger.Info("semantic search enabled for notes")
		}
	}

	server := mcpkg.NewServer(
		noteStore,
		activityStore,
		projectStore,
		collectedStore,
		statsStore,
		taskStore,
		contentStore,
		sessionStore,
		goalStore,
		logger,
		opts...,
	)

	switch cfg.Transport {
	case "stdio":
		logger.Info("starting MCP server over stdio")
		return server.Run(ctx)

	case "http":
		return runHTTP(ctx, &cfg, server, logger)

	default:
		return fmt.Errorf("unknown MCP_TRANSPORT: %q (use \"http\" or \"stdio\")", cfg.Transport)
	}
}

func runHTTP(ctx context.Context, cfg *config, server *mcpkg.Server, logger *slog.Logger) error {
	if cfg.MCPToken == "" {
		return fmt.Errorf("MCP_TOKEN is required for HTTP transport")
	}
	if cfg.GoogleClientID == "" || cfg.GoogleClientSecret == "" || cfg.AdminEmail == "" {
		return fmt.Errorf("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and ADMIN_EMAIL are required for HTTP transport")
	}

	oauth := mcpkg.NewOAuthProvider(mcpkg.OAuthConfig{
		StaticToken: cfg.MCPToken,
		AdminEmail:  cfg.AdminEmail,
		BaseURL:     "https://mcp.koopa0.dev",
		GoogleOAuth: &oauth2.Config{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURL:  "https://mcp.koopa0.dev/oauth/google/callback",
			Scopes:       []string{"openid", "email"},
			Endpoint:     google.Endpoint,
		},
	}, logger)

	handler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return server.MCPServer()
	}, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://koopa0.dev/favicon.ico", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		// Claude Code CLI sends Authorization header — it already has a Bearer token
		// and doesn't need OAuth discovery. Return 404 so it skips OAuth flow
		// and uses the Bearer token directly. Claude.ai web doesn't send
		// Authorization on this endpoint, so OAuth flow works normally for it.
		if r.Header.Get("Authorization") != "" {
			http.NotFound(w, r)
			return
		}
		oauth.Metadata(w, r)
	})
	mux.HandleFunc("/oauth/authorize", oauth.Authorize)
	mux.HandleFunc("GET /oauth/google/callback", oauth.GoogleCallback)
	mux.HandleFunc("POST /oauth/token", oauth.Token)
	mux.HandleFunc("POST /oauth/register", oauth.Register)
	mux.Handle("/mcp", mcpkg.BearerAuth(handler, oauth))

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      120 * time.Second, // long: MCP uses SSE streaming
		IdleTimeout:       600 * time.Second, // 10 min: keep MCP connections alive between tool calls
	}

	go func() {
		<-ctx.Done()
		close(oauth.Done)
		_ = httpServer.Close()
	}()

	logger.Info("starting MCP server over HTTP", "port", cfg.Port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}

// notionAdapter bridges the Notion client to mcpkg.NotionTaskWriter.
// Stores a single Client instance so the rate limiter is shared across calls.
type notionAdapter struct {
	client *notion.Client
}

func (a notionAdapter) UpdatePageStatus(ctx context.Context, pageID, status string) error {
	return a.client.UpdatePageStatus(ctx, pageID, status)
}

func (a notionAdapter) UpdatePageProperties(ctx context.Context, pageID string, properties map[string]any) error {
	return a.client.UpdatePageProperties(ctx, pageID, properties)
}

func (a notionAdapter) CreateTask(ctx context.Context, p *mcpkg.NotionCreateTaskParams) (string, error) {
	return a.client.CreateTask(ctx, &notion.CreateTaskParams{
		DatabaseID:  p.DatabaseID,
		Title:       p.Title,
		DueDate:     p.DueDate,
		Description: p.Description,
		Priority:    p.Priority,
		Energy:      p.Energy,
		MyDay:       p.MyDay,
		ProjectID:   p.ProjectID,
	})
}

// geminiQueryEmbedder generates query embedding vectors via Gemini.
type geminiQueryEmbedder struct {
	g        *genkit.Genkit
	embedder ai.Embedder
}

func newGeminiQueryEmbedder(ctx context.Context, logger *slog.Logger) (*geminiQueryEmbedder, error) {
	googleAI := &googlegenai.GoogleAI{}
	g := genkit.Init(ctx, genkit.WithPlugins(googleAI))

	embedder, err := googleAI.DefineEmbedder(g, "gemini-embedding-2-preview", &ai.EmbedderOptions{})
	if err != nil {
		return nil, fmt.Errorf("defining embedder: %w", err)
	}
	logger.Info("gemini embedder initialized for semantic search")
	return &geminiQueryEmbedder{g: g, embedder: embedder}, nil
}

func (e *geminiQueryEmbedder) EmbedQuery(ctx context.Context, text string) (pgvector.Vector, error) {
	resp, err := genkit.Embed(ctx, e.g,
		ai.WithEmbedder(e.embedder),
		ai.WithTextDocs(text),
		ai.WithConfig(&genai.EmbedContentConfig{
			OutputDimensionality: genai.Ptr[int32](768),
		}),
	)
	if err != nil {
		return pgvector.Vector{}, fmt.Errorf("embedding query: %w", err)
	}
	if len(resp.Embeddings) == 0 || len(resp.Embeddings[0].Embedding) == 0 {
		return pgvector.Vector{}, fmt.Errorf("empty embedding response")
	}
	return pgvector.NewVector(resp.Embeddings[0].Embedding), nil
}

// httpPipelineTrigger triggers pipelines via the admin API.
// It self-signs a short-lived JWT using the shared JWT_SECRET,
// so no separate ADMIN_API_TOKEN is needed.
type httpPipelineTrigger struct {
	baseURL    string
	jwtSecret  []byte
	adminEmail string
	logger     *slog.Logger
}

func (t *httpPipelineTrigger) TriggerCollect(ctx context.Context) {
	t.post(ctx, "/api/admin/pipeline/collect")
}

func (t *httpPipelineTrigger) TriggerNotionSync(ctx context.Context) {
	t.post(ctx, "/api/admin/pipeline/notion-sync")
}

func (t *httpPipelineTrigger) signToken() (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"email": t.adminEmail,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(t.jwtSecret)
}

func (t *httpPipelineTrigger) post(ctx context.Context, path string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL+path, http.NoBody)
	if err != nil {
		t.logger.Error("creating pipeline trigger request", "path", path, "error", err)
		return
	}
	signed, err := t.signToken()
	if err != nil {
		t.logger.Error("signing admin jwt", "error", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+signed)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.logger.Error("triggering pipeline", "path", path, "error", err)
		return
	}
	resp.Body.Close()
	t.logger.Info("pipeline triggered via admin API", "path", path, "status", resp.StatusCode)
}

// httpFlowInvoker removed — invoke_content_polish and invoke_content_strategy
// no longer exposed as MCP tools (AI-calls-AI anti-pattern).
// Genkit flows remain in internal/ai/ for potential non-LLM consumers.
