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
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/goal"
	mcpserver "github.com/koopa0/blog-backend/internal/mcp"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/stats"
	"github.com/koopa0/blog-backend/internal/task"
)

func main() {
	// MCP stdio uses stdout — always log to stderr.
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		logger.Error("DATABASE_URL is required")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, dbURL, logger)
	stop()
	if err != nil {
		logger.Error("MCP server stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dbURL string, logger *slog.Logger) error {
	poolCfg, err := pgxpool.ParseConfig(dbURL)
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

	server := mcpserver.NewServer(
		note.NewStore(pool),
		activity.NewStore(pool),
		project.NewStore(pool),
		collected.NewStore(pool),
		stats.NewStore(pool),
		task.NewStore(pool),
		content.NewStore(pool),
		goal.NewStore(pool),
		logger,
	)

	transport := envOr("MCP_TRANSPORT", "http")

	switch transport {
	case "stdio":
		logger.Info("starting MCP server over stdio")
		return server.Run(ctx)

	case "http":
		token := os.Getenv("MCP_TOKEN")
		if token == "" {
			return fmt.Errorf("MCP_TOKEN is required for HTTP transport")
		}
		port := envOr("MCP_PORT", "8081")

		handler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
			return server.MCPServer()
		}, nil)

		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, "ok")
		})
		mux.Handle("/mcp", bearerAuth(handler, token))

		httpServer := &http.Server{
			Addr:              ":" + port,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}

		go func() {
			<-ctx.Done()
			_ = httpServer.Close()
		}()

		logger.Info("starting MCP server over HTTP", "port", port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("http server: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unknown MCP_TRANSPORT: %q (use \"http\" or \"stdio\")", transport)
	}
}

// bearerAuth wraps an http.Handler with bearer token authentication.
func bearerAuth(next http.Handler, token string) http.Handler {
	tokenBytes := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), tokenBytes) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
