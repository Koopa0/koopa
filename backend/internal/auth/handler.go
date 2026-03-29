package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/koopa0/blog-backend/internal/api"
)

const (
	accessTokenDuration  = 24 * time.Hour
	refreshTokenDuration = 7 * 24 * time.Hour
	stateMaxAge          = 5 * time.Minute

	// maxGoogleOAuthResponseSize is the upper bound for Google OAuth API responses (1 MB).
	// The userinfo endpoint returns a small JSON payload (~200 bytes). 1 MB is generous
	// enough to never truncate legitimate responses while capping memory usage.
	maxGoogleOAuthResponseSize = 1 << 20
)

// Handler handles authentication HTTP requests.
type Handler struct {
	store       *Store
	secret      []byte
	oauthCfg    *oauth2.Config
	adminEmail  string
	frontendURL string
	logger      *slog.Logger
}

// NewHandler returns an auth Handler configured for Google OAuth.
func NewHandler(store *Store, jwtSecret string, gcfg *GoogleConfig, logger *slog.Logger) *Handler {
	return &Handler{
		store:  store,
		secret: []byte(jwtSecret),
		oauthCfg: &oauth2.Config{
			ClientID:     gcfg.ClientID,
			ClientSecret: gcfg.ClientSecret,
			RedirectURL:  gcfg.RedirectURI,
			Scopes:       []string{"openid", "email"},
			Endpoint:     google.Endpoint,
		},
		adminEmail:  gcfg.AdminEmail,
		frontendURL: gcfg.FrontendURL,
		logger:      logger,
	}
}

// GoogleLogin handles GET /api/auth/google — returns Google OAuth URL for the frontend to redirect.
func (h *Handler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	state := h.generateState()
	authURL := h.oauthCfg.AuthCodeURL(state, oauth2.SetAuthURLParam("login_hint", h.adminEmail))
	api.Encode(w, http.StatusOK, api.Response{Data: map[string]string{"url": authURL}})
}

// GoogleCallback handles GET /api/auth/google/callback — exchanges code for tokens.
func (h *Handler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if !h.validateState(state) {
		h.redirectError(w, r, "invalid or expired OAuth state")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.redirectError(w, r, "missing authorization code")
		return
	}

	token, err := h.oauthCfg.Exchange(r.Context(), code)
	if err != nil {
		h.logger.Error("exchanging OAuth code", "error", err)
		h.redirectError(w, r, "failed to exchange authorization code")
		return
	}

	email, err := h.fetchGoogleEmail(r.Context(), token)
	if err != nil {
		h.logger.Error("fetching Google userinfo", "error", err)
		h.redirectError(w, r, "failed to get user info from Google")
		return
	}

	email = strings.ToLower(email)

	if !strings.EqualFold(email, h.adminEmail) {
		h.logger.Warn("unauthorized OAuth login attempt", "email", email)
		h.redirectError(w, r, "unauthorized")
		return
	}

	user, err := h.store.UpsertUserByEmail(r.Context(), email)
	if err != nil {
		h.logger.Error("upserting user", "error", err)
		h.redirectError(w, r, "internal error")
		return
	}

	pair, err := h.issueTokenPair(r.Context(), user)
	if err != nil {
		h.logger.Error("issuing token pair", "error", err)
		h.redirectError(w, r, "failed to issue tokens")
		return
	}

	// Use URL fragment (#) instead of query string (?) to prevent tokens from
	// appearing in server logs and Referer headers. Note: fragments ARE stored
	// in browser history — the Angular callback page should call
	// history.replaceState to clear them after reading.
	q := url.Values{}
	q.Set("access_token", pair.AccessToken)
	q.Set("refresh_token", pair.RefreshToken)
	h.jsRedirect(w, h.frontendURL+"/admin/oauth-callback#"+q.Encode())
}

// Refresh handles POST /api/auth/refresh.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[RefreshRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if req.RefreshToken == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "refresh_token is required")
		return
	}

	tokenHash := hashToken(req.RefreshToken)

	// Atomic consume: DELETE ... RETURNING ensures only one concurrent
	// request can successfully consume a given refresh token.
	stored, err := h.store.ConsumeRefreshToken(r.Context(), tokenHash)
	if err != nil {
		api.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid refresh token")
		return
	}

	if time.Now().After(stored.ExpiresAt) {
		api.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "refresh token expired")
		return
	}

	user, err := h.store.UserByID(r.Context(), stored.UserID)
	if err != nil {
		h.logger.Error("looking up user for refresh", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to issue tokens")
		return
	}

	pair, err := h.issueTokenPair(r.Context(), user)
	if err != nil {
		h.logger.Error("issuing token pair", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to issue tokens")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: pair})
}

func (h *Handler) issueTokenPair(ctx context.Context, user *User) (*TokenPair, error) {
	accessToken, err := h.signAccessToken(user.Email)
	if err != nil {
		return nil, fmt.Errorf("signing access token: %w", err)
	}

	refreshToken, err := h.createRefreshToken(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("creating refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (h *Handler) signAccessToken(email string) (string, error) {
	now := time.Now()
	claims := Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenDuration)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(h.secret)
}

func (h *Handler) createRefreshToken(ctx context.Context, userID uuid.UUID) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}

	tokenStr := base64.URLEncoding.EncodeToString(raw)
	tokenHash := hashToken(tokenStr)
	expiresAt := time.Now().Add(refreshTokenDuration)

	if err := h.store.CreateRefreshToken(ctx, userID, tokenHash, expiresAt); err != nil {
		return "", fmt.Errorf("storing refresh token: %w", err)
	}

	return tokenStr, nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(h[:])
}

// generateState creates an HMAC-signed timestamp for OAuth state parameter.
func (h *Handler) generateState() string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	// Add random nonce to ensure uniqueness within the same second.
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		// crypto/rand failure is fatal — cannot generate secure state.
		panic("crypto/rand: " + err.Error())
	}
	payload := ts + "." + base64.URLEncoding.EncodeToString(nonce)
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(payload))
	sig := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig
}

// validateState checks that the state is a valid HMAC-signed timestamp within maxAge.
func (h *Handler) validateState(state string) bool {
	// Format: ts.nonce.sig — find the last dot to split payload from signature.
	lastDot := strings.LastIndex(state, ".")
	if lastDot < 0 {
		return false
	}
	payload := state[:lastDot]
	sig := state[lastDot+1:]

	// Extract timestamp from payload (first segment before first dot).
	ts, _, _ := strings.Cut(payload, ".")

	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}

	// Reject states that are too old OR in the future (prevents never-expiring states).
	stateTime := time.Unix(unix, 0)
	age := time.Since(stateTime)
	if age < 0 || age > stateMaxAge {
		return false
	}

	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(payload))
	expected := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}

// googleUserInfo is the response from Google's userinfo endpoint.
type googleUserInfo struct {
	Email string `json:"email"`
}

// fetchGoogleEmail calls Google's userinfo endpoint to get the user's email.
func (h *Handler) fetchGoogleEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	client := h.oauthCfg.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", fmt.Errorf("calling userinfo endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo returned status %d", resp.StatusCode)
	}

	var info googleUserInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxGoogleOAuthResponseSize)).Decode(&info); err != nil {
		return "", fmt.Errorf("decoding userinfo: %w", err)
	}

	if info.Email == "" {
		return "", fmt.Errorf("no email in userinfo response")
	}

	return info.Email, nil
}

// redirectError redirects the user to the frontend login page with an error message.
func (h *Handler) redirectError(w http.ResponseWriter, _ *http.Request, msg string) {
	q := url.Values{}
	q.Set("error", msg)
	h.jsRedirect(w, h.frontendURL+"/login?"+q.Encode())
}

// jsRedirect writes an HTML page that redirects via JavaScript.
// This avoids 302 redirects that BFF proxies may follow server-side.
// Only https: and http: URLs are allowed — rejects javascript:, data:, etc.
func (h *Handler) jsRedirect(w http.ResponseWriter, target string) {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		h.logger.Warn("jsRedirect: rejected non-http(s) URL", "target", target)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Use json.Marshal for safe JS string escaping (handles </script>, quotes, etc.)
	jsStr, err := json.Marshal(target)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><body><script>window.location.href=%s;</script></body></html>`, jsStr)
}
