// Package auth provides JWT authentication, login, and refresh token rotation.
package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// User represents an admin user.
type User struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
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
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// LoginRequest is the payload for POST /api/auth/login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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

var (
	// ErrInvalidCredentials indicates wrong email or password.
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrTokenExpired indicates the token has expired.
	ErrTokenExpired = errors.New("token expired")

	// ErrInvalidToken indicates the token is malformed or invalid.
	ErrInvalidToken = errors.New("invalid token")

	// ErrNotFound indicates the requested record does not exist.
	ErrNotFound = errors.New("not found")
)
