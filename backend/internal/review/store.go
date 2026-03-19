package review

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store handles database operations for the review queue.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// Create inserts a new review queue entry.
// If a pending review already exists for this content, it returns nil (no-op).
func (s *Store) Create(ctx context.Context, contentID uuid.UUID, reviewLevel string, notes *string) (*Review, error) {
	exists, err := s.q.PendingReviewExistsForContent(ctx, contentID)
	if err != nil {
		return nil, fmt.Errorf("checking pending review for content %s: %w", contentID, err)
	}
	if exists {
		return nil, nil
	}
	r, err := s.q.CreateReview(ctx, db.CreateReviewParams{
		ContentID:     contentID,
		ReviewLevel:   db.ReviewLevel(reviewLevel),
		ReviewerNotes: notes,
	})
	if err != nil {
		return nil, fmt.Errorf("creating review for content %s: %w", contentID, err)
	}
	return &Review{
		ID:            r.ID,
		ContentID:     r.ContentID,
		ReviewLevel:   r.RqReviewLevel,
		Status:        r.RqStatus,
		ReviewerNotes: r.ReviewerNotes,
		SubmittedAt:   r.SubmittedAt,
		ReviewedAt:    r.ReviewedAt,
	}, nil
}

// PendingReviews returns all pending review items.
func (s *Store) PendingReviews(ctx context.Context) ([]Review, error) {
	rows, err := s.q.PendingReviews(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing pending reviews: %w", err)
	}
	reviews := make([]Review, len(rows))
	for i, r := range rows {
		reviews[i] = Review{
			ID:            r.ID,
			ContentID:     r.ContentID,
			ReviewLevel:   r.RqReviewLevel,
			Status:        r.RqStatus,
			ReviewerNotes: r.ReviewerNotes,
			SubmittedAt:   r.SubmittedAt,
			ReviewedAt:    r.ReviewedAt,
			ContentTitle:  r.ContentTitle,
			ContentType:   r.ContentType,
		}
	}
	return reviews, nil
}

// Review returns a single review by ID.
func (s *Store) Review(ctx context.Context, id uuid.UUID) (*Review, error) {
	r, err := s.q.ReviewByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying review %s: %w", id, err)
	}
	return &Review{
		ID:            r.ID,
		ContentID:     r.ContentID,
		ReviewLevel:   r.RqReviewLevel,
		Status:        r.RqStatus,
		ReviewerNotes: r.ReviewerNotes,
		SubmittedAt:   r.SubmittedAt,
		ReviewedAt:    r.ReviewedAt,
	}, nil
}

// ApproveReview marks a review as approved.
func (s *Store) ApproveReview(ctx context.Context, id uuid.UUID) error {
	err := s.q.ApproveReview(ctx, id)
	if err != nil {
		return fmt.Errorf("approving review %s: %w", id, err)
	}
	return nil
}

// RejectReview marks a review as rejected with notes.
func (s *Store) RejectReview(ctx context.Context, id uuid.UUID, notes string) error {
	err := s.q.RejectReview(ctx, db.RejectReviewParams{
		ID:            id,
		ReviewerNotes: &notes,
	})
	if err != nil {
		return fmt.Errorf("rejecting review %s: %w", id, err)
	}
	return nil
}
