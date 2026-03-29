package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// OAuthConfig holds the parameters needed to create an OAuthProvider.
type OAuthConfig struct {
	StaticToken string         // MCP_TOKEN — accepted directly as Bearer token
	AdminEmail  string         // only this email can authorize
	BaseURL     string         // public URL (e.g. "https://mcp.koopa0.dev")
	GoogleOAuth *oauth2.Config // Google OAuth2 configuration
}

// codeInfo stores an authorization code with its PKCE challenge.
type codeInfo struct {
	codeChallenge string
	expiresAt     time.Time
}

// pendingAuth stores an in-flight OAuth authorize request while the user
// authenticates with Google.
type pendingAuth struct {
	clientID      string
	redirectURI   string
	state         string // MCP client's state — returned unchanged
	codeChallenge string
	expiresAt     time.Time
}

// maxClients is the upper bound on dynamic client registrations.
// Prevents memory exhaustion from automated registration spam.
const maxClients = 100

// OAuthProvider implements OAuth 2.1 with Google login and PKCE for the MCP server.
type OAuthProvider struct {
	staticToken string // MCP_TOKEN — accepted directly as Bearer token
	baseURL     string
	adminEmail  string
	googleOAuth *oauth2.Config
	logger      *slog.Logger

	mu           sync.Mutex
	clients      map[string]string      // client_id -> client_secret
	tokens       map[string]time.Time   // access_token -> expiry
	refreshToks  map[string]time.Time   // refresh_token -> expiry
	codes        map[string]codeInfo    // authorization_code -> info
	pendingAuths map[string]pendingAuth // session_id -> pending authorize request

	Done chan struct{}
}

// NewOAuthProvider creates an OAuthProvider and starts its cleanup goroutine.
func NewOAuthProvider(cfg OAuthConfig, logger *slog.Logger) *OAuthProvider {
	o := &OAuthProvider{
		staticToken:  cfg.StaticToken,
		baseURL:      cfg.BaseURL,
		adminEmail:   cfg.AdminEmail,
		googleOAuth:  cfg.GoogleOAuth,
		logger:       logger,
		clients:      make(map[string]string),
		tokens:       make(map[string]time.Time),
		refreshToks:  make(map[string]time.Time),
		codes:        make(map[string]codeInfo),
		pendingAuths: make(map[string]pendingAuth),
		Done:         make(chan struct{}),
	}
	go o.cleanup()
	return o
}

// cleanup periodically evicts expired entries to prevent memory leaks.
func (o *OAuthProvider) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-o.Done:
			return
		case now := <-ticker.C:
			o.evictExpired(now)
		}
	}
}

func (o *OAuthProvider) evictExpired(now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for tok, exp := range o.tokens {
		if now.After(exp) {
			delete(o.tokens, tok)
		}
	}
	for code, ci := range o.codes {
		if now.After(ci.expiresAt) {
			delete(o.codes, code)
		}
	}
	for rt, exp := range o.refreshToks {
		if now.After(exp) {
			delete(o.refreshToks, rt)
		}
	}
	for sid, pa := range o.pendingAuths {
		if now.After(pa.expiresAt) {
			delete(o.pendingAuths, sid)
		}
	}
}

// ValidToken checks if a token is the static MCP_TOKEN or a valid OAuth-issued token.
func (o *OAuthProvider) ValidToken(tok string) bool {
	if subtle.ConstantTimeCompare([]byte(tok), []byte(o.staticToken)) == 1 {
		return true
	}
	o.mu.Lock()
	exp, ok := o.tokens[tok]
	o.mu.Unlock()
	return ok && time.Now().Before(exp)
}

func (o *OAuthProvider) issueToken() (accessToken string, accessTTL time.Duration, refreshToken string, refreshTTL time.Duration) { //nolint:unparam // refreshTTL used internally for storage
	ab := make([]byte, 32)
	_, _ = rand.Read(ab)
	accessToken = hex.EncodeToString(ab)
	accessTTL = 1 * time.Hour

	rb := make([]byte, 32)
	_, _ = rand.Read(rb)
	refreshToken = "rt_" + hex.EncodeToString(rb)
	refreshTTL = 30 * 24 * time.Hour

	o.mu.Lock()
	o.tokens[accessToken] = time.Now().Add(accessTTL)
	o.refreshToks[refreshToken] = time.Now().Add(refreshTTL)
	o.mu.Unlock()
	return
}

func (o *OAuthProvider) consumeRefreshToken(rt string) bool {
	o.mu.Lock()
	exp, ok := o.refreshToks[rt]
	if ok {
		delete(o.refreshToks, rt)
	}
	o.mu.Unlock()
	return ok && time.Now().Before(exp)
}

// issueCode creates a one-time authorization code bound to a PKCE challenge.
func (o *OAuthProvider) issueCode(codeChallenge string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	code := hex.EncodeToString(b)
	o.mu.Lock()
	o.codes[code] = codeInfo{
		codeChallenge: codeChallenge,
		expiresAt:     time.Now().Add(5 * time.Minute),
	}
	o.mu.Unlock()
	return code
}

// consumeCode validates and removes an authorization code, returning its info.
func (o *OAuthProvider) consumeCode(code string) (codeInfo, bool) {
	o.mu.Lock()
	ci, ok := o.codes[code]
	if ok {
		delete(o.codes, code)
	}
	o.mu.Unlock()
	if !ok || time.Now().After(ci.expiresAt) {
		return codeInfo{}, false
	}
	return ci, true
}

// verifyPKCE checks that SHA256(code_verifier) matches the stored code_challenge.
func verifyPKCE(codeVerifier, codeChallenge string) bool {
	if codeVerifier == "" || codeChallenge == "" {
		return false
	}
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}

// Metadata handles GET /.well-known/oauth-authorization-server.
func (o *OAuthProvider) Metadata(w http.ResponseWriter, _ *http.Request) {
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
var allowedRedirectPrefixes = []string{
	"https://claude.ai/",
	"http://localhost:",
	"http://127.0.0.1:",
}

func validRedirectURI(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Host == "" {
		return false
	}
	// Reject URLs with userinfo — prevents authority confusion attacks
	// like http://localhost:80@evil.com/ which passes prefix check but
	// redirects the browser to evil.com.
	if parsed.User != nil {
		return false
	}
	// Catch edge cases url.Parse doesn't flag as User (e.g., /@evil.com paths).
	if strings.Contains(parsed.Host+parsed.Path, "@") {
		return false
	}

	for _, prefix := range allowedRedirectPrefixes {
		if strings.HasPrefix(uri, prefix) {
			return true
		}
	}
	return false
}

// Authorize handles GET/POST /oauth/authorize.
// Instead of auto-approving, it redirects to Google OAuth for authentication.
func (o *OAuthProvider) Authorize(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

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
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		http.Error(w, "PKCE S256 code_challenge required", http.StatusBadRequest)
		return
	}

	// Store the pending authorization request keyed by a random session ID.
	sessionBytes := make([]byte, 16)
	_, _ = rand.Read(sessionBytes)
	sessionID := hex.EncodeToString(sessionBytes)

	o.mu.Lock()
	o.pendingAuths[sessionID] = pendingAuth{
		clientID:      clientID,
		redirectURI:   redirectURI,
		state:         state,
		codeChallenge: codeChallenge,
		expiresAt:     time.Now().Add(10 * time.Minute),
	}
	o.mu.Unlock()

	// Redirect to Google OAuth with the session ID as state.
	googleURL := o.googleOAuth.AuthCodeURL(sessionID, oauth2.SetAuthURLParam("login_hint", o.adminEmail))
	http.Redirect(w, r, googleURL, http.StatusFound)
}

// GoogleCallback handles GET /oauth/google/callback.
// Verifies the Google login, checks admin email, then issues an MCP authorization
// code and redirects back to the MCP client (e.g. Claude.ai).
func (o *OAuthProvider) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("state")
	googleCode := r.URL.Query().Get("code")
	if sessionID == "" || googleCode == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	// Look up the pending authorization request.
	o.mu.Lock()
	pa, ok := o.pendingAuths[sessionID]
	if ok {
		delete(o.pendingAuths, sessionID)
	}
	o.mu.Unlock()
	if !ok || time.Now().After(pa.expiresAt) {
		http.Error(w, "authorization session expired", http.StatusBadRequest)
		return
	}

	// Exchange Google authorization code for token.
	googleToken, err := o.googleOAuth.Exchange(r.Context(), googleCode)
	if err != nil {
		o.logger.Error("exchanging Google OAuth code", "error", err)
		http.Error(w, "failed to authenticate with Google", http.StatusInternalServerError)
		return
	}

	// Fetch user email from Google.
	email, err := fetchGoogleEmail(r.Context(), o.googleOAuth, googleToken)
	if err != nil {
		o.logger.Error("fetching Google email", "error", err)
		http.Error(w, "failed to get user info", http.StatusInternalServerError)
		return
	}

	// Only the admin can authorize.
	if !strings.EqualFold(email, o.adminEmail) {
		o.logger.Warn("unauthorized MCP OAuth attempt", "email", email)
		http.Error(w, "unauthorized: only the admin can connect", http.StatusForbidden)
		return
	}

	// Issue MCP authorization code bound to the PKCE challenge.
	mcpCode := o.issueCode(pa.codeChallenge)

	// Redirect back to the MCP client's redirect_uri.
	loc := pa.redirectURI + "?code=" + url.QueryEscape(mcpCode)
	if pa.state != "" {
		loc += "&state=" + url.QueryEscape(pa.state)
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

// fetchGoogleEmail calls Google's userinfo endpoint to get the user's email.
func fetchGoogleEmail(ctx context.Context, cfg *oauth2.Config, token *oauth2.Token) (string, error) {
	client := cfg.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", fmt.Errorf("calling userinfo endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo returned status %d", resp.StatusCode)
	}

	var info struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return "", fmt.Errorf("decoding userinfo: %w", err)
	}
	if info.Email == "" {
		return "", fmt.Errorf("no email in userinfo response")
	}
	return info.Email, nil
}

// Token handles POST /oauth/token.
func (o *OAuthProvider) Token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
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
		ci, valid := o.consumeCode(code)
		if !valid {
			jsonError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		// PKCE verification: SHA256(code_verifier) must match stored code_challenge.
		codeVerifier := r.FormValue("code_verifier")
		if !verifyPKCE(codeVerifier, ci.codeChallenge) {
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

// Register handles POST /oauth/register (dynamic client registration per MCP spec).
func (o *OAuthProvider) Register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Generate client credentials outside the lock (crypto/rand is safe).
	cidBytes := make([]byte, 16)
	csecBytes := make([]byte, 32)
	_, _ = rand.Read(cidBytes)
	_, _ = rand.Read(csecBytes)
	cid := hex.EncodeToString(cidBytes)
	csec := hex.EncodeToString(csecBytes)

	// Atomic check-and-insert under a single lock hold to prevent TOCTOU race.
	o.mu.Lock()
	if len(o.clients) >= maxClients {
		o.mu.Unlock()
		http.Error(w, "too many registered clients", http.StatusServiceUnavailable)
		return
	}
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

func (o *OAuthProvider) checkClientCredentials(r *http.Request) bool {
	cid := r.FormValue("client_id")
	csec := r.FormValue("client_secret")
	if cid == "" || csec == "" {
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

// BearerAuth wraps an http.Handler, accepting either the static MCP_TOKEN
// or any OAuth-issued access token.
func BearerAuth(next http.Handler, oauth *OAuthProvider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tok := auth[len(prefix):]
		if !oauth.ValidToken(tok) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
