// Command mcp runs a Model Context Protocol server, exposing the koopa0.dev
// knowledge engine as workflow-driven tools (v2).
//
// Transport is selected by the MCP_TRANSPORT env var:
//   - "http" (default): Streamable HTTP on MCP_PORT (default 8081), requires MCP_TOKEN
//   - "stdio": stdio transport for local Claude Code usage
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/directive"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/insight"
	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/learnsession"
	mcpkg "github.com/Koopa0/koopa0.dev/internal/mcp"
	"github.com/Koopa0/koopa0.dev/internal/mcpauth"
	"github.com/Koopa0/koopa0.dev/internal/project"
	"github.com/Koopa0/koopa0.dev/internal/report"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := loadConfig(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, &cfg, logger)
	stop()
	if err != nil {
		logger.Error("MCP server stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *config, logger *slog.Logger) error {
	pool, err := connectDB(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	taipeiLoc, locErr := time.LoadLocation("Asia/Taipei")
	if locErr != nil {
		return fmt.Errorf("loading Asia/Taipei timezone: %w", locErr)
	}

	server := mcpkg.NewServer(
		task.NewStore(pool),
		journal.NewStore(pool),
		daily.NewStore(pool),
		content.NewStore(pool),
		project.NewStore(pool),
		goal.NewStore(pool),
		directive.NewStore(pool),
		report.NewStore(pool),
		insight.NewStore(pool),
		learnsession.NewStore(pool),
		logger,
		mcpkg.WithLocation(taipeiLoc),
		mcpkg.WithParticipant(cfg.Participant),
	)

	switch cfg.Transport {
	case "stdio":
		logger.Info("starting MCP v2 server over stdio")
		return server.MCPServer().Run(ctx, &mcp.StdioTransport{})
	case "http":
		return runHTTP(ctx, cfg, server, logger)
	default:
		return fmt.Errorf("unknown MCP_TRANSPORT: %q (use \"http\" or \"stdio\")", cfg.Transport)
	}
}

func connectDB(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing DATABASE_URL: %w", err)
	}
	poolCfg.MaxConns = 5

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}
	return pool, nil
}

func runHTTP(ctx context.Context, cfg *config, server *mcpkg.Server, logger *slog.Logger) error {
	if cfg.MCPToken == "" {
		return fmt.Errorf("MCP_TOKEN is required for HTTP transport")
	}
	if cfg.GoogleClientID == "" || cfg.GoogleClientSecret == "" || cfg.AdminEmail == "" {
		return fmt.Errorf("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and ADMIN_EMAIL are required for HTTP transport")
	}

	oauth := mcpauth.New(mcpauth.Config{
		StaticToken: cfg.MCPToken,
		AdminEmail:  cfg.AdminEmail,
		BaseURL:     cfg.MCPBaseURL,
		GoogleOAuth: &oauth2.Config{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURL:  cfg.MCPBaseURL + "/oauth/google/callback",
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
	mux.Handle("/mcp", mcpauth.BearerAuth(handler, oauth))

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       600 * time.Second,
	}

	go func() {
		<-ctx.Done()
		close(oauth.Done)
		_ = httpServer.Close()
	}()

	logger.Info("starting MCP v2 server over HTTP", "port", cfg.Port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}
