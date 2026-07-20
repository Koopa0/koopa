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
	"strings"
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
			IsPublic: r.IsPublic, ProjectID: r.ProjectID,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
			SourceVaultPath: r.SourceVaultPath, SourceGitBlobSHA: r.SourceGitBlobSha,
			PublishedAt: r.PublishedAt, WithdrawnAt: r.WithdrawnAt,
			WithdrawalReason: r.WithdrawalReason,
			CreatedAt:        r.CreatedAt, UpdatedAt: r.UpdatedAt,
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

// Publish is the state- and provenance-guarded transition behind the admin
// publish handler. Policy:
//
//   - draft     → published   the owner publishes a source-bound snapshot
//     reverted from review without requiring another review detour
//   - review    → published   the owner publishes an agent-submitted snapshot
//     from the review queue (agents never publish)
//   - published+public → published+public idempotent no-op
//   - published+withdrawn → ErrInvalidState (restore is a named transition)
//   - changes_requested, archived, … → ErrInvalidState
//   - missing id               → ErrNotFound
//
// A draft/review row without a complete Vault path + Git blob SHA returns
// ErrSourceRequired. The guarded UPDATE is the authority boundary; the
// read-after-rejection below only classifies a miss and cannot authorize it.
func (s *Store) Publish(ctx context.Context, id uuid.UUID) (*Content, error) {
	return s.PublishContent(ctx, id)
}

// PublishContent atomically promotes a source-bound draft/review snapshot.
// Kept as the store-level entry point used by existing internal callers; it
// enforces the same guard as Publish and cannot bypass provenance.
func (s *Store) PublishContent(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.PublishContent(ctx, id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("publishing content %s: %w", id, err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return s.classifyPublishRejection(ctx, id)
	}

	c := rowToContent(contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		SourceVaultPath: r.SourceVaultPath, SourceGitBlobSHA: r.SourceGitBlobSha,
		PublishedAt: r.PublishedAt, WithdrawnAt: r.WithdrawnAt,
		WithdrawalReason: r.WithdrawalReason,
		CreatedAt:        r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})

	topics, err := s.TopicsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Topics = topics

	return &c, nil
}

func (s *Store) classifyPublishRejection(ctx context.Context, id uuid.UUID) (*Content, error) {
	current, err := s.Content(ctx, id)
	if err != nil {
		return nil, err
	}
	if current.Status == StatusPublished && current.IsPublic {
		return current, nil
	}
	if (current.Status == StatusDraft || current.Status == StatusReview) && current.Source() == nil {
		return nil, ErrSourceRequired
	}
	return nil, ErrInvalidState
}

// Withdraw stops serving a historically published snapshot while preserving
// its publication status, date, authored bytes, and source coordinate. The
// guarded UPDATE and audit trigger commit current state and receipt atomically.
func (s *Store) Withdraw(ctx context.Context, id uuid.UUID, reason string) (*Content, error) {
	reason = strings.TrimSpace(reason)
	if err := CheckWithdrawalReason(reason); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	if containsProseControlChars(reason) {
		return nil, fmt.Errorf("%w: withdrawal reason must not contain control characters", ErrInvalidInput)
	}

	r, err := s.q.WithdrawContent(ctx, db.WithdrawContentParams{ID: id, WithdrawalReason: &reason})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, s.transitionRejectionReason(ctx, id)
		}
		return nil, fmt.Errorf("withdrawing content %s: %w", id, err)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		CreatedBy: r.CreatedBy, ProposalRationale: r.ProposalRationale,
		ReviewNote:      r.ReviewNote,
		SourceVaultPath: r.SourceVaultPath, SourceGitBlobSHA: r.SourceGitBlobSha,
		PublishedAt: r.PublishedAt, WithdrawnAt: r.WithdrawnAt,
		WithdrawalReason: r.WithdrawalReason,
		CreatedAt:        r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// Restore resumes serving the exact withdrawn publication snapshot. The audit
// trigger captures the prior withdrawal metadata before the current fields are
// cleared; authored bytes and published_at remain unchanged.
func (s *Store) Restore(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.RestoreContent(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, s.transitionRejectionReason(ctx, id)
		}
		return nil, fmt.Errorf("restoring content %s: %w", id, err)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		CreatedBy: r.CreatedBy, ProposalRationale: r.ProposalRationale,
		ReviewNote:      r.ReviewNote,
		SourceVaultPath: r.SourceVaultPath, SourceGitBlobSHA: r.SourceGitBlobSha,
		PublishedAt: r.PublishedAt, WithdrawnAt: r.WithdrawnAt,
		WithdrawalReason: r.WithdrawalReason,
		CreatedAt:        r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// SubmitContentForReview transitions a source-bound draft to review atomically.
// Missing provenance returns ErrSourceRequired; an existing row in another
// state returns ErrInvalidState; a missing id returns ErrNotFound. The guarded
// UPDATE owns the transition and the rejection lookup is read-only.
func (s *Store) SubmitContentForReview(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.SubmitContentForReview(ctx, id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("submitting content %s for review: %w", id, err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, s.submitRejectionReason(ctx, id)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		SourceVaultPath: r.SourceVaultPath, SourceGitBlobSHA: r.SourceGitBlobSha,
		PublishedAt: r.PublishedAt, WithdrawnAt: r.WithdrawnAt,
		WithdrawalReason: r.WithdrawalReason,
		CreatedAt:        r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

func (s *Store) submitRejectionReason(ctx context.Context, id uuid.UUID) error {
	current, err := s.Content(ctx, id)
	if err != nil {
		return err
	}
	if current.Status == StatusDraft && current.Source() == nil {
		return ErrSourceRequired
	}
	return ErrInvalidState
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
		IsPublic: r.IsPublic, ProjectID: r.ProjectID,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		SourceVaultPath: r.SourceVaultPath, SourceGitBlobSHA: r.SourceGitBlobSha,
		PublishedAt: r.PublishedAt, WithdrawnAt: r.WithdrawnAt,
		WithdrawalReason: r.WithdrawalReason,
		CreatedAt:        r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// ArchiveContentReturning archives content and returns the updated row. Both
// the REST archive endpoint and DeleteContent call it; DeleteContent discards
// the row but relies on the RETURNING to detect a missing id (ErrNotFound).
func (s *Store) ArchiveContentReturning(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.ArchiveContentReturning(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, s.transitionRejectionReason(ctx, id)
		}
		return nil, fmt.Errorf("archiving content %s: %w", id, err)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		SourceVaultPath: r.SourceVaultPath, SourceGitBlobSHA: r.SourceGitBlobSha,
		PublishedAt: r.PublishedAt, WithdrawnAt: r.WithdrawnAt,
		WithdrawalReason: r.WithdrawalReason,
		CreatedAt:        r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// ReviseByCreator applies the caller-scoped revise_content edit: an agent
// revises content IT created that is in review or changes_requested, returning
// it to review and clearing the owner's review_note. createdBy is the resolved
// caller identity — caller-scoped, never a client-supplied filter — so a
// mismatched creator, a wrong status, or an unknown id all match 0 rows and
// return ErrNotFound. A same-SHA retry returns ErrSourceUnchanged without
// changing any authored field; the classifier query is guarded by the same
// caller and status predicates, so it does not reveal another agent's row.
func (s *Store) ReviseByCreator(ctx context.Context, p *RevisionParams) (*Content, error) {
	if err := ValidateSourceSnapshot(p.SourceVaultPath, p.SourceGitBlobSHA); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	r, err := s.q.ReviseContentByCreator(ctx, db.ReviseContentByCreatorParams{
		ID:               p.ID,
		CreatedBy:        &p.CreatedBy,
		Body:             p.Body,
		Excerpt:          p.Excerpt,
		Title:            p.Title,
		SourceVaultPath:  &p.SourceVaultPath,
		SourceGitBlobSha: &p.SourceGitBlobSHA,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("revising content %s created by %q: %w", p.ID, p.CreatedBy, err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, s.reviseRejectionReason(ctx, p)
	}
	return s.hydrateContentRow(ctx, r.ID, &contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		CreatedBy: r.CreatedBy, ProposalRationale: r.ProposalRationale,
		ReviewNote:      r.ReviewNote,
		SourceVaultPath: r.SourceVaultPath, SourceGitBlobSHA: r.SourceGitBlobSha,
		PublishedAt: r.PublishedAt, WithdrawnAt: r.WithdrawnAt,
		WithdrawalReason: r.WithdrawalReason,
		CreatedAt:        r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

func (s *Store) reviseRejectionReason(ctx context.Context, p *RevisionParams) error {
	existingSHA, err := s.q.RevisableContentSourceByCreator(ctx, db.RevisableContentSourceByCreatorParams{
		ID: p.ID, CreatedBy: &p.CreatedBy,
	})
	if err == nil && existingSHA != nil && *existingSHA == p.SourceGitBlobSHA {
		return ErrSourceUnchanged
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("classifying rejected revision %s: %w", p.ID, err)
	}
	return ErrNotFound
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
		IsPublic: r.IsPublic, ProjectID: r.ProjectID,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		CreatedBy: r.CreatedBy, ProposalRationale: r.ProposalRationale,
		ReviewNote:      r.ReviewNote,
		SourceVaultPath: r.SourceVaultPath, SourceGitBlobSHA: r.SourceGitBlobSha,
		PublishedAt: r.PublishedAt, WithdrawnAt: r.WithdrawnAt,
		WithdrawalReason: r.WithdrawalReason,
		CreatedAt:        r.CreatedAt, UpdatedAt: r.UpdatedAt,
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
