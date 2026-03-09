package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/koopa0/blog-backend/internal/api"
)

const (
	accessTokenDuration  = 15 * time.Minute
	refreshTokenDuration = 7 * 24 * time.Hour
)

// Handler handles authentication HTTP requests.
type Handler struct {
	store  *Store
	secret []byte
	logger *slog.Logger
}

// NewHandler returns an auth Handler.
func NewHandler(store *Store, secret string, logger *slog.Logger) *Handler {
	return &Handler{
		store:  store,
		secret: []byte(secret),
		logger: logger,
	}
}

// Login handles POST /api/auth/login.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[LoginRequest](r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "email and password are required")
		return
	}

	user, err := h.store.UserByEmail(r.Context(), req.Email)
	if err != nil {
		api.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		api.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
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

// Refresh handles POST /api/auth/refresh.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[RefreshRequest](r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if req.RefreshToken == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "refresh_token is required")
		return
	}

	tokenHash := hashToken(req.RefreshToken)

	stored, err := h.store.RefreshTokenByHash(r.Context(), tokenHash)
	if err != nil {
		api.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid refresh token")
		return
	}

	if time.Now().After(stored.ExpiresAt) {
		// best-effort: delete expired token
		_ = h.store.DeleteRefreshToken(r.Context(), tokenHash)
		api.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "refresh token expired")
		return
	}

	// rotate: delete old token
	if err := h.store.DeleteRefreshToken(r.Context(), tokenHash); err != nil {
		h.logger.Error("deleting old refresh token", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to rotate token")
		return
	}

	pair, err := h.issueTokenPairFromID(r.Context(), stored.UserID)
	if err != nil {
		h.logger.Error("issuing token pair", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to issue tokens")
		return
	}

	api.Encode(w, http.StatusOK, api.Response{Data: pair})
}

func (h *Handler) issueTokenPair(ctx context.Context, user *User) (*TokenPair, error) {
	accessToken, err := h.signAccessToken(user.ID.String(), user.Email, user.Role)
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

func (h *Handler) issueTokenPairFromID(ctx context.Context, userID uuid.UUID) (*TokenPair, error) {
	user, err := h.store.UserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("looking up user: %w", err)
	}
	return h.issueTokenPair(ctx, user)
}

func (h *Handler) signAccessToken(userID, email, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
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
