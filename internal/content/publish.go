// Copyright 2026 Koopa. All rights reserved.

// publish.go owns the publication-related store methods: state-based
// reads (ByStatus, PublishedForRSS, AllPublishedSlugs) and the
// PublishContent mutation that promotes a draft to published. The
// mutation is co-located with its read neighbours because the handler
// calls the reads immediately before and after the transition.

package content

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/db"
)

// ByStatus returns contents filtered by status, limited to limit results.
func (s *Store) ByStatus(ctx context.Context, status string, limit int) ([]Content, error) {
	rows, err := s.q.ContentsByStatus(ctx, db.ContentsByStatusParams{
		Status:     db.ContentStatus(status),
		MaxResults: int32(limit), // #nosec G115 -- bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("listing contents by status %q: %w", status, err)
	}
	contents := make([]Content, len(rows))
	for i := range rows {
		r := &rows[i]
		contents[i] = rowToContent(contentRow{
			ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
			Type: r.Type, Status: r.Status,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
			PublishedAt: r.PublishedAt,
			CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
	}
	return contents, nil
}

// PublishedForRSS returns recent published content for RSS feed.
func (s *Store) PublishedForRSS(ctx context.Context, limit int) ([]Content, error) {
	rows, err := s.q.PublishedForRSS(ctx, int32(limit)) // #nosec G115 -- RSS limit is a small constant, not user-controlled
	if err != nil {
		return nil, fmt.Errorf("listing contents for rss: %w", err)
	}
	contents := make([]Content, len(rows))
	for i, r := range rows {
		contents[i] = Content{
			ID:          r.ID,
			Slug:        r.Slug,
			Title:       r.Title,
			Excerpt:     r.Excerpt,
			Type:        Type(r.Type),
			PublishedAt: r.PublishedAt,
			UpdatedAt:   r.UpdatedAt,
		}
	}
	return contents, nil
}

// AllPublishedSlugs returns all published content slugs for sitemap.
func (s *Store) AllPublishedSlugs(ctx context.Context) ([]Content, error) {
	rows, err := s.q.AllPublishedSlugs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing slugs for sitemap: %w", err)
	}
	contents := make([]Content, len(rows))
	for i, r := range rows {
		contents[i] = Content{
			Slug:      r.Slug,
			Type:      Type(r.Type),
			UpdatedAt: r.UpdatedAt,
		}
	}
	return contents, nil
}

// PublishedInWindow returns the content published within [since, until], for
// review_period.published_content. status='published' guarantees published_at is
// non-null (chk_content_publication), so the window filter is well-defined.
// Read-only; the returned rows carry only the display fields the retrospective
// needs (title, type, published_at).
func (s *Store) PublishedInWindow(ctx context.Context, since, until time.Time) ([]Content, error) {
	rows, err := s.q.PublishedContentsInWindow(ctx, db.PublishedContentsInWindowParams{Since: &since, Until: &until})
	if err != nil {
		return nil, fmt.Errorf("listing content published in window: %w", err)
	}
	contents := make([]Content, len(rows))
	for i := range rows {
		r := &rows[i]
		contents[i] = Content{
			Title:       r.Title,
			Type:        Type(r.Type),
			PublishedAt: r.PublishedAt,
		}
	}
	return contents, nil
}

// Publish is the state-guarded publish transition behind the admin publish
// handler — the owner's gate that promotes a content to published. Policy:
//
//   - draft     → published   the owner publishes a finished draft directly,
//     the common path (Koopa finalises offline, then publishes — no review detour)
//   - review    → published   the owner publishes an agent-proposed draft from
//     the review queue (agents reach review via propose_content; they never publish)
//   - published → published    idempotent no-op (row unchanged, no second audit event)
//   - changes_requested, archived, … → ErrInvalidState
//   - missing id               → ErrNotFound
//
// Promotion sets is_public + published_at. It reads the current row then acts;
// callers run inside an admin / actor transaction, so the read and the
// conditional write share one tx.
//
// Concurrency: publish is the owner's terminal decision and wins races — a
// concurrent agent revise_content on the same row is rejected (not-found) by
// revise_content's status guard, by design.
func (s *Store) Publish(ctx context.Context, id uuid.UUID) (*Content, error) {
	current, err := s.Content(ctx, id)
	if err != nil {
		return nil, err // pgx.ErrNoRows already mapped to ErrNotFound by Content
	}
	switch current.Status {
	case StatusDraft, StatusReview:
		return s.PublishContent(ctx, id)
	case StatusPublished:
		return current, nil // idempotent: already published, no re-mutation
	default:
		return nil, ErrInvalidState
	}
}

// PublishContent sets content status to published, is_public=true, and
// published_at — at the store layer this is UNCONDITIONAL (no source-status
// guard). It is the low-level mutation that Publish delegates to once the
// source state has been validated. Callers that need the editorial gate
// (draft/review-promote, published-idempotent, changes_requested/archived-rejected)
// MUST go through Publish, not call this directly on an unvalidated id.
func (s *Store) PublishContent(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.PublishContent(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("publishing content %s: %w", id, err)
	}

	c := rowToContent(contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})

	topics, err := s.TopicsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Topics = topics

	return &c, nil
}

// SubmitContentForReview transitions a draft content to review atomically.
// Returns ErrInvalidState if the content exists but is not in draft,
// ErrNotFound if the id does not exist at all. The conditional UPDATE is
// race-safe; the extra existence lookup only runs on the rejection path
// to distinguish "wrong status" from "no such row" for correct HTTP mapping.
func (s *Store) SubmitContentForReview(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.SubmitContentForReview(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, s.transitionRejectionReason(ctx, id)
		}
		return nil, fmt.Errorf("submitting content %s for review: %w", id, err)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// RevertContentToDraft transitions a review content back to draft atomically.
// Returns ErrInvalidState if the content exists but is not in review,
// ErrNotFound if the id does not exist. Same race-safety rationale as
// SubmitContentForReview.
func (s *Store) RevertContentToDraft(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.RevertContentToDraft(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, s.transitionRejectionReason(ctx, id)
		}
		return nil, fmt.Errorf("reverting content %s to draft: %w", id, err)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// ArchiveContentReturning archives content and returns the updated row. Both
// the REST archive endpoint and DeleteContent call it; DeleteContent discards
// the row but relies on the RETURNING to detect a missing id (ErrNotFound).
func (s *Store) ArchiveContentReturning(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.ArchiveContentReturning(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("archiving content %s: %w", id, err)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// ReviseByCreator applies the caller-scoped revise_content edit: an agent
// revises content IT created that is in review or changes_requested, returning
// it to review and clearing the owner's review_note. createdBy is the resolved
// caller identity — caller-scoped, never a client-supplied filter — so a
// mismatched creator, a wrong status, or an unknown id all match 0 rows and
// return ErrNotFound. The single sentinel is deliberate: a caller-scoped miss
// must NOT leak whether the row exists, belongs to someone else, or is in a
// non-revisable state. Body / Excerpt / Title are optional (nil leaves the
// column unchanged via COALESCE).
func (s *Store) ReviseByCreator(ctx context.Context, p RevisionParams) (*Content, error) {
	r, err := s.q.ReviseContentByCreator(ctx, db.ReviseContentByCreatorParams{
		ID:        p.ID,
		CreatedBy: &p.CreatedBy,
		Body:      p.Body,
		Excerpt:   p.Excerpt,
		Title:     p.Title,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("revising content %s created by %q: %w", p.ID, p.CreatedBy, err)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		CreatedBy: r.CreatedBy, ProposalRationale: r.ProposalRationale,
		ReviewNote:  r.ReviewNote,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// SendBackForChanges is the admin send-back transition: the owner returns a
// review draft to its authoring agent for revision (review → changes_requested)
// with reviewNote carrying the revision reason. Returns ErrInvalidState when the
// content exists but is not in review, ErrNotFound when the id does not exist.
// Same race-safety rationale as SubmitContentForReview: the conditional UPDATE
// is the gate, the extra lookup only runs on the rejection path to distinguish
// "wrong status" from "no such row" for correct HTTP mapping.
func (s *Store) SendBackForChanges(ctx context.Context, id uuid.UUID, reviewNote string) (*Content, error) {
	r, err := s.q.SendContentChangesRequested(ctx, db.SendContentChangesRequestedParams{
		ID:         id,
		ReviewNote: &reviewNote,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, s.transitionRejectionReason(ctx, id)
		}
		return nil, fmt.Errorf("sending content %s back for changes: %w", id, err)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		CreatedBy: r.CreatedBy, ProposalRationale: r.ProposalRationale,
		ReviewNote:  r.ReviewNote,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// transitionRejectionReason maps a conditional-UPDATE miss to the right
// sentinel — ErrNotFound when the id does not exist, ErrInvalidState when
// the row exists but its status did not satisfy the transition guard.
func (s *Store) transitionRejectionReason(ctx context.Context, id uuid.UUID) error {
	if _, err := s.q.ContentByID(ctx, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("checking content %s existence: %w", id, err)
	}
	return ErrInvalidState
}

// hydrateContentRow attaches topics to a Content produced by a
// state-transition query. Shared between all transitions that return the
// updated row.
func (s *Store) hydrateContentRow(ctx context.Context, id uuid.UUID, row *contentRow) (*Content, error) {
	c := rowToContent(*row)
	topics, err := s.TopicsForContent(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("hydrating topics for content %s: %w", id, err)
	}
	c.Topics = topics
	return &c, nil
}
