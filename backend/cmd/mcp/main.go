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
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/goal"
	mcpserver "github.com/koopa0/blog-backend/internal/mcp"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/notion"
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

	contentStore := content.NewStore(pool)
	taskStore := task.NewStore(pool)

	var opts []mcpserver.ServerOption
	notionKey := os.Getenv("NOTION_API_KEY")
	taskDBID := os.Getenv("NOTION_TASKS_DB_ID")
	if notionKey != "" && taskDBID != "" {
		opts = append(opts, mcpserver.WithNotionTaskWriter(
			notionAdapter{apiKey: notionKey},
			taskDBID,
		))
	}

	server := mcpserver.NewServer(
		note.NewStore(pool),
		activity.NewStore(pool),
		project.NewStore(pool),
		collected.NewStore(pool),
		stats.NewStore(pool),
		taskStore,
		taskStore,
		contentStore,
		contentStore,
		goal.NewStore(pool),
		logger,
		opts...,
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

		clientID := envOr("MCP_OAUTH_CLIENT_ID", "claude-ai")
		clientSecret := envOr("MCP_OAUTH_CLIENT_SECRET", token)

		oauth := newOAuthProvider(clientID, clientSecret, port)

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
		mux.HandleFunc("GET /.well-known/oauth-authorization-server", oauth.metadata)
		mux.HandleFunc("/oauth/authorize", oauth.authorize)
		mux.HandleFunc("POST /oauth/token", oauth.token)
		mux.HandleFunc("POST /oauth/register", oauth.register)
		mux.Handle("/mcp", bearerAuth(handler, oauth))

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

// bearerAuth wraps an http.Handler, accepting either the static MCP_TOKEN
// or any OAuth-issued access token.
func bearerAuth(next http.Handler, oauth *oauthProvider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tok := auth[len(prefix):]
		if !oauth.validToken(tok) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Minimal OAuth 2.0 provider (client_credentials + authorization_code) ---

type oauthProvider struct {
	clientID     string
	clientSecret string
	baseURL      string

	mu     sync.Mutex
	tokens map[string]time.Time // access_token → expiry
	codes  map[string]time.Time // authorization_code → expiry
}

func newOAuthProvider(clientID, clientSecret, port string) *oauthProvider {
	return &oauthProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		baseURL:      "https://mcp.koopa0.dev",
		tokens:       make(map[string]time.Time),
		codes:        make(map[string]time.Time),
	}
}

func (o *oauthProvider) validToken(tok string) bool {
	// Accept static MCP_TOKEN (backwards compat with Claude Code).
	if subtle.ConstantTimeCompare([]byte(tok), []byte(o.clientSecret)) == 1 {
		return true
	}
	// Accept OAuth-issued tokens.
	o.mu.Lock()
	exp, ok := o.tokens[tok]
	o.mu.Unlock()
	return ok && time.Now().Before(exp)
}

func (o *oauthProvider) issueToken() (string, time.Duration) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	ttl := 24 * time.Hour
	o.mu.Lock()
	o.tokens[tok] = time.Now().Add(ttl)
	o.mu.Unlock()
	return tok, ttl
}

func (o *oauthProvider) issueCode() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	code := hex.EncodeToString(b)
	o.mu.Lock()
	o.codes[code] = time.Now().Add(5 * time.Minute)
	o.mu.Unlock()
	return code
}

func (o *oauthProvider) consumeCode(code string) bool {
	o.mu.Lock()
	exp, ok := o.codes[code]
	if ok {
		delete(o.codes, code)
	}
	o.mu.Unlock()
	return ok && time.Now().Before(exp)
}

// GET /.well-known/oauth-authorization-server
func (o *oauthProvider) metadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"issuer":                                o.baseURL,
		"authorization_endpoint":                o.baseURL + "/oauth/authorize",
		"token_endpoint":                        o.baseURL + "/oauth/token",
		"registration_endpoint":                 o.baseURL + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// GET/POST /oauth/authorize — simplified: auto-approve and redirect with code.
func (o *oauthProvider) authorize(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	if redirectURI == "" {
		http.Error(w, "redirect_uri required", http.StatusBadRequest)
		return
	}
	code := o.issueCode()
	loc := redirectURI + "?code=" + code
	if state != "" {
		loc += "&state=" + state
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

// POST /oauth/token
func (o *oauthProvider) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "client_credentials":
		if !o.checkClientCredentials(r) {
			jsonError(w, "invalid_client", http.StatusUnauthorized)
			return
		}
	case "authorization_code":
		code := r.FormValue("code")
		if !o.consumeCode(code) {
			jsonError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
	default:
		jsonError(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}

	tok, ttl := o.issueToken()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(ttl.Seconds()),
	})
}

// POST /oauth/register — dynamic client registration (MCP spec requirement).
// For a personal server we just echo back the client_id.
func (o *oauthProvider) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"client_id":     o.clientID,
		"client_secret": o.clientSecret,
		"redirect_uris": req.RedirectURIs,
		"client_name":   req.ClientName,
	})
}

func (o *oauthProvider) checkClientCredentials(r *http.Request) bool {
	cid := r.FormValue("client_id")
	csec := r.FormValue("client_secret")
	if cid == "" || csec == "" {
		// Try HTTP Basic Auth.
		cid, csec, _ = r.BasicAuth()
	}
	return subtle.ConstantTimeCompare([]byte(cid), []byte(o.clientID)) == 1 &&
		subtle.ConstantTimeCompare([]byte(csec), []byte(o.clientSecret)) == 1
}

func jsonError(w http.ResponseWriter, errCode string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": errCode})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// notionAdapter bridges the Notion client to mcpserver.NotionTaskWriter.
type notionAdapter struct {
	apiKey string
}

func (a notionAdapter) UpdatePageStatus(ctx context.Context, pageID, status string) error {
	return notion.NewClient(a.apiKey).UpdatePageStatus(ctx, pageID, status)
}

func (a notionAdapter) CreateTask(ctx context.Context, p mcpserver.NotionCreateTaskParams) error {
	return notion.NewClient(a.apiKey).CreateTask(ctx, notion.CreateTaskParams{
		DatabaseID:  p.DatabaseID,
		Title:       p.Title,
		DueDate:     p.DueDate,
		Description: p.Description,
	})
}
