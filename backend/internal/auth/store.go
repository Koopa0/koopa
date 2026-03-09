package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store handles database operations for auth.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{q: db.New(pool)}
}

// UserByID returns the user with the given ID.
func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	row, err := s.q.UserByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying user by id: %w", err)
	}
	return &User{
		ID:           row.ID,
		Email:        row.Email,
		PasswordHash: row.PasswordHash,
		Role:         row.Role,
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
	}, nil
}

// UserByEmail returns the user with the given email.
func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	row, err := s.q.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying user by email: %w", err)
	}
	return &User{
		ID:           row.ID,
		Email:        row.Email,
		PasswordHash: row.PasswordHash,
		Role:         row.Role,
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
	}, nil
}

// CreateRefreshToken stores a new refresh token hash.
func (s *Store) CreateRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	err := s.q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return fmt.Errorf("creating refresh token: %w", err)
	}
	return nil
}

// RefreshTokenByHash returns the refresh token with the given hash.
func (s *Store) RefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	row, err := s.q.RefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying refresh token: %w", err)
	}
	return &RefreshToken{
		ID:        row.ID,
		UserID:    row.UserID,
		TokenHash: row.TokenHash,
		ExpiresAt: row.ExpiresAt,
		CreatedAt: row.CreatedAt,
	}, nil
}

// DeleteRefreshToken removes a refresh token by hash.
func (s *Store) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	err := s.q.DeleteRefreshToken(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("deleting refresh token: %w", err)
	}
	return nil
}

// DeleteExpiredTokens removes all expired refresh tokens.
func (s *Store) DeleteExpiredTokens(ctx context.Context) error {
	err := s.q.DeleteExpiredTokens(ctx)
	if err != nil {
		return fmt.Errorf("deleting expired tokens: %w", err)
	}
	return nil
}
