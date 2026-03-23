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
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	pgvector "github.com/pgvector/pgvector-go"
	"google.golang.org/genai"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/goal"
	mcpserver "github.com/koopa0/blog-backend/internal/mcp"
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

	notionStore := notion.NewStore(pool)
	projectStore := project.NewStore(pool)
	goalStore := goal.NewStore(pool)
	collectedStore := collected.NewStore(pool)
	activityStore := activity.NewStore(pool)
	sessionStore := session.NewStore(pool)

	var opts []mcpserver.ServerOption
	notionKey := os.Getenv("NOTION_API_KEY")
	if notionKey != "" {
		logger.Info("notion write tools enabled")
		opts = append(opts, mcpserver.WithNotionTaskWriter(
			notionAdapter{client: notion.NewClient(notionKey)},
			notionStore,
		))
	} else {
		logger.Warn("NOTION_API_KEY not set — create_task and complete_task will be unavailable")
	}
	opts = append(opts,
		mcpserver.WithGoalWriter(goalStore),
		mcpserver.WithProjectWriter(projectStore),
		mcpserver.WithCollectedLatest(collectedStore),
		mcpserver.WithCollectedHighlights(collectedStore),
		mcpserver.WithContentSearcher(contentStore),
		mcpserver.WithSessionNotes(sessionStore, sessionStore),
		mcpserver.WithActivityWriter(activityStore),
	)

	// Optional semantic search (requires GEMINI_API_KEY)
	noteStore := note.NewStore(pool)
	if geminiKey := os.Getenv("GEMINI_API_KEY"); geminiKey != "" {
		qe, embedErr := newGeminiQueryEmbedder(ctx, logger)
		if embedErr != nil {
			logger.Warn("semantic search unavailable", "error", embedErr)
		} else {
			opts = append(opts, mcpserver.WithSemanticSearch(noteStore, qe))
			logger.Info("semantic search enabled for notes")
		}
	}

	server := mcpserver.NewServer(
		noteStore,
		activityStore,
		projectStore,
		collectedStore,
		stats.NewStore(pool),
		taskStore,
		taskStore,
		contentStore,
		contentStore,
		goalStore,
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

		oauth := newOAuthProvider(token)

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
			oauth.metadata(w, r)
		})
		mux.HandleFunc("/oauth/authorize", oauth.authorize)
		mux.HandleFunc("POST /oauth/token", oauth.token)
		mux.HandleFunc("POST /oauth/register", oauth.register)
		mux.Handle("/mcp", bearerAuth(handler, oauth))

		httpServer := &http.Server{
			Addr:              ":" + port,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      120 * time.Second, // long: MCP uses SSE streaming
			IdleTimeout:       600 * time.Second, // 10 min: keep MCP connections alive between tool calls
		}

		go func() {
			<-ctx.Done()
			close(oauth.done)
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
	staticToken string // MCP_TOKEN — accepted directly as Bearer token
	baseURL     string

	mu            sync.Mutex
	clients       map[string]string    // client_id → client_secret (dynamic registrations)
	tokens        map[string]time.Time // access_token → expiry
	refreshTokens map[string]time.Time // refresh_token → expiry
	codes         map[string]time.Time // authorization_code → expiry

	done chan struct{} // signals cleanup goroutine to stop
}

func newOAuthProvider(staticToken string) *oauthProvider {
	o := &oauthProvider{
		staticToken:   staticToken,
		baseURL:       "https://mcp.koopa0.dev",
		clients:       make(map[string]string),
		tokens:        make(map[string]time.Time),
		refreshTokens: make(map[string]time.Time),
		codes:         make(map[string]time.Time),
		done:          make(chan struct{}),
	}
	go o.cleanup()
	return o
}

// cleanup periodically evicts expired tokens and codes to prevent memory leaks.
func (o *oauthProvider) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-o.done:
			return
		case now := <-ticker.C:
			o.mu.Lock()
			for tok, exp := range o.tokens {
				if now.After(exp) {
					delete(o.tokens, tok)
				}
			}
			for code, exp := range o.codes {
				if now.After(exp) {
					delete(o.codes, code)
				}
			}
			for rt, exp := range o.refreshTokens {
				if now.After(exp) {
					delete(o.refreshTokens, rt)
				}
			}
			o.mu.Unlock()
		}
	}
}

func (o *oauthProvider) validToken(tok string) bool {
	// Accept static MCP_TOKEN (Bearer token from .mcp.json headers).
	if subtle.ConstantTimeCompare([]byte(tok), []byte(o.staticToken)) == 1 {
		return true
	}
	// Accept OAuth-issued tokens.
	o.mu.Lock()
	exp, ok := o.tokens[tok]
	o.mu.Unlock()
	return ok && time.Now().Before(exp)
}

func (o *oauthProvider) issueToken() (accessToken string, accessTTL time.Duration, refreshToken string, refreshTTL time.Duration) {
	ab := make([]byte, 32)
	_, _ = rand.Read(ab)
	accessToken = hex.EncodeToString(ab)
	accessTTL = 1 * time.Hour

	rb := make([]byte, 32)
	_, _ = rand.Read(rb)
	refreshToken = "rt_" + hex.EncodeToString(rb)
	refreshTTL = 30 * 24 * time.Hour // 30 days

	o.mu.Lock()
	o.tokens[accessToken] = time.Now().Add(accessTTL)
	o.refreshTokens[refreshToken] = time.Now().Add(refreshTTL)
	o.mu.Unlock()
	return
}

// consumeRefreshToken validates and rotates a refresh token.
// Returns false if the token is invalid or expired.
func (o *oauthProvider) consumeRefreshToken(rt string) bool {
	o.mu.Lock()
	exp, ok := o.refreshTokens[rt]
	if ok {
		delete(o.refreshTokens, rt) // single-use: rotate on each refresh
	}
	o.mu.Unlock()
	return ok && time.Now().Before(exp)
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
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                o.baseURL,
		"authorization_endpoint":                o.baseURL + "/oauth/authorize",
		"token_endpoint":                        o.baseURL + "/oauth/token",
		"registration_endpoint":                 o.baseURL + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// allowedRedirectPrefixes lists the accepted redirect_uri prefixes.
// Only Claude.ai and local dev are permitted.
var allowedRedirectPrefixes = []string{
	"https://claude.ai/",
	"http://localhost:",
	"http://127.0.0.1:",
}

// validRedirectURI checks that the redirect_uri starts with an allowed prefix.
func validRedirectURI(uri string) bool {
	for _, prefix := range allowedRedirectPrefixes {
		if strings.HasPrefix(uri, prefix) {
			return true
		}
	}
	return false
}

// GET/POST /oauth/authorize — simplified: auto-approve and redirect with code.
func (o *oauthProvider) authorize(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	clientID := r.FormValue("client_id")
	if redirectURI == "" {
		http.Error(w, "redirect_uri required", http.StatusBadRequest)
		return
	}
	if !validRedirectURI(redirectURI) {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}
	o.mu.Lock()
	_, knownClient := o.clients[clientID]
	o.mu.Unlock()
	if !knownClient {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	code := o.issueCode()
	loc := redirectURI + "?code=" + url.QueryEscape(code)
	if state != "" {
		loc += "&state=" + url.QueryEscape(state)
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
		if !o.checkClientCredentials(r) {
			jsonError(w, "invalid_client", http.StatusUnauthorized)
			return
		}
		code := r.FormValue("code")
		if !o.consumeCode(code) {
			jsonError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
	case "refresh_token":
		rt := r.FormValue("refresh_token")
		if !o.consumeRefreshToken(rt) {
			jsonError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
	default:
		jsonError(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}

	accessTok, accessTTL, refreshTok, _ := o.issueToken()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  accessTok,
		"refresh_token": refreshTok,
		"token_type":    "Bearer",
		"expires_in":    int(accessTTL.Seconds()),
	})
}

// POST /oauth/register — dynamic client registration (MCP spec requirement).
// Each registration gets a unique client_id + client_secret pair.
func (o *oauthProvider) register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Generate unique credentials per registration.
	cidBytes := make([]byte, 16)
	csecBytes := make([]byte, 32)
	_, _ = rand.Read(cidBytes)
	_, _ = rand.Read(csecBytes)
	cid := hex.EncodeToString(cidBytes)
	csec := hex.EncodeToString(csecBytes)

	o.mu.Lock()
	o.clients[cid] = csec
	o.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client_id":     cid,
		"client_secret": csec,
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
	if cid == "" || csec == "" {
		return false
	}
	o.mu.Lock()
	storedSecret, ok := o.clients[cid]
	o.mu.Unlock()
	return ok && subtle.ConstantTimeCompare([]byte(csec), []byte(storedSecret)) == 1
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
// Stores a single Client instance so the rate limiter is shared across calls.
type notionAdapter struct {
	client *notion.Client
}

func (a notionAdapter) UpdatePageStatus(ctx context.Context, pageID, status string) error {
	return a.client.UpdatePageStatus(ctx, pageID, status)
}

func (a notionAdapter) CreateTask(ctx context.Context, p mcpserver.NotionCreateTaskParams) (string, error) {
	return a.client.CreateTask(ctx, notion.CreateTaskParams{
		DatabaseID:  p.DatabaseID,
		Title:       p.Title,
		DueDate:     p.DueDate,
		Description: p.Description,
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
