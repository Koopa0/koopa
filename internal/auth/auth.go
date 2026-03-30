// Package auth provides Google OAuth 2.0 login, JWT access tokens, and refresh token rotation.
package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// User represents an admin user.
type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RefreshToken represents a stored refresh token.
type RefreshToken struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	TokenHash string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// Claims are the JWT claims for an access token.
type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// RefreshRequest is the payload for POST /api/auth/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// TokenPair is the response containing access and refresh tokens.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// GoogleConfig holds Google OAuth 2.0 settings.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	AdminEmail   string
	FrontendURL  string
}

var (
	// ErrNotFound indicates the requested record does not exist.
	ErrNotFound = errors.New("auth: not found")

	// ErrConflict indicates a unique constraint violation (e.g. duplicate refresh token hash).
	ErrConflict = errors.New("auth: conflict")
)
