// store.go holds the Store for tags + tag_aliases, including:
//
//   - ResolveTag / ResolveTags — the 4-step normalization pipeline
//     (exact alias → case-insensitive alias → slug → unmapped). New
//     mappings are inserted best-effort so the next lookup is O(1).
//   - MergeTags — the manual tag-consolidation path. Every step is
//     explicit and transactional because the ON DELETE CASCADE on
//     the junction tables would silently wipe history if the merge
//     hit DeleteTag without first reassigning aliases / content_tags
//     / bookmark_tags. Do NOT simplify this to a single DELETE —
//     the data-loss bug it prevents is documented in the MergeTags
//     block comment above that method.
//
// `maxRawTagLen = 255` silently drops oversized inputs to unmapped —
// the pipeline treats them as hostile and never inserts an alias.

package tag

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

// Store manages canonical tag registry and the alias normalization pipeline.
type Store struct {
	q *db.Queries
}

// NewStore returns a tag Store backed by the given connection (pool or tx).
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by callers
// composing multi-store transactions — typically via api.ActorMiddleware
// (HTTP) or mcp.Server.withActorTx (MCP). The tx carries koopa.actor
// so audit triggers attribute mutations correctly.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// maxRawTagLen is the maximum length for a raw tag string.
// Tags exceeding this are silently dropped to prevent abuse via oversized YAML values.
const maxRawTagLen = 255

// ResolveTag runs the 4-step normalization pipeline for a single raw tag:
//  1. Exact alias match
//  2. Case-insensitive alias match
//  3. Slug match against canonical tags
//  4. Insert unmapped alias for admin review
func (s *Store) ResolveTag(ctx context.Context, rawTag string) Resolved {
	if len(rawTag) > maxRawTagLen {
		return Resolved{RawTag: rawTag, TagID: nil, ResolutionSource: "unmapped"}
	}
	// Step 0: if admin has rejected this raw tag, skip all resolution steps.
	rejected, err := s.q.IsAliasRejected(ctx, rawTag)
	if err == nil && rejected {
		return Resolved{RawTag: rawTag, TagID: nil, ResolutionSource: "unmapped"}
	}

	// Step 1: exact alias match
	alias, err := s.q.AliasByExactRawTag(ctx, rawTag)
	if err == nil && alias.TagID != nil {
		return Resolved{RawTag: rawTag, TagID: alias.TagID, ResolutionSource: "auto-exact"}
	}

	// Step 2: case-insensitive alias match
	alias, err = s.q.AliasByCaseInsensitiveRawTag(ctx, rawTag)
	if err == nil && alias.TagID != nil {
		// Auto-create exact alias for future lookups
		_ = s.q.InsertAliasWithTag(ctx, db.InsertAliasWithTagParams{
			RawTag:           rawTag,
			TagID:            alias.TagID,
			ResolutionSource: "auto-ci",
		}) // best-effort
		return Resolved{RawTag: rawTag, TagID: alias.TagID, ResolutionSource: "auto-ci"}
	}

	// Step 3: slug match against canonical tags
	slug := Slugify(rawTag)
	if slug != "" {
		t, err := s.q.TagBySlug(ctx, slug)
		if err == nil {
			tagID := t.ID
			// Auto-create alias for future lookups
			_ = s.q.InsertAliasWithTag(ctx, db.InsertAliasWithTagParams{
				RawTag:           rawTag,
				TagID:            &tagID,
				ResolutionSource: "auto-slug",
			}) // best-effort
			return Resolved{RawTag: rawTag, TagID: &tagID, ResolutionSource: "auto-slug"}
		}
	}

	// Step 4: unmapped — insert alias with NULL tag_id for admin review
	_ = s.q.InsertUnmappedAlias(ctx, rawTag) // best-effort, ON CONFLICT DO NOTHING
	return Resolved{RawTag: rawTag, TagID: nil, ResolutionSource: "unmapped"}
}

// ResolveTags normalizes a slice of raw tags through the 4-step pipeline.
// Uses a batch exact-match lookup first to resolve the majority in one query,
// then falls back to per-tag resolution for the unresolved remainder.
func (s *Store) ResolveTags(ctx context.Context, rawTags []string) []Resolved {
	if len(rawTags) == 0 {
		return nil
	}

	results := make([]Resolved, 0, len(rawTags))

	// Step 1: batch exact alias match — resolves majority of tags in one query.
	aliases, err := s.q.AliasesByExactRawTags(ctx, rawTags)
	if err != nil {
		// Fall back to per-tag resolution on batch query failure.
		for _, raw := range rawTags {
			results = append(results, s.ResolveTag(ctx, raw))
		}
		return results
	}

	// Index matched aliases by raw_tag for O(1) lookup.
	matched := make(map[string]*uuid.UUID, len(aliases))
	for _, a := range aliases {
		matched[a.RawTag] = a.TagID
	}

	// Resolve each tag: use batch result if available, fall back to per-tag.
	for _, raw := range rawTags {
		if tagID, ok := matched[raw]; ok {
			results = append(results, Resolved{RawTag: raw, TagID: tagID, ResolutionSource: "auto-exact"})
			continue
		}
		// Not in batch result — run the full 4-step pipeline for this tag only.
		results = append(results, s.ResolveTag(ctx, raw))
	}
	return results
}

// Tags returns all canonical tags ordered by name.
func (s *Store) Tags(ctx context.Context) ([]Tag, error) {
	rows, err := s.q.ListTags(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing tags: %w", err)
	}
	tags := make([]Tag, len(rows))
	for i := range rows {
		tags[i] = tagFromDB(&rows[i])
	}
	return tags, nil
}

// Tag returns a single canonical tag by ID.
func (s *Store) Tag(ctx context.Context, id uuid.UUID) (*Tag, error) {
	row, err := s.q.TagByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying tag %s: %w", id, err)
	}
	t := tagFromDB(&row)
	return &t, nil
}

// CreateTag inserts a new canonical tag.
func (s *Store) CreateTag(ctx context.Context, p *CreateParams) (*Tag, error) {
	row, err := s.q.CreateTag(ctx, db.CreateTagParams{
		Slug:        p.Slug,
		Name:        p.Name,
		ParentID:    p.ParentID,
		Description: p.Description,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating tag: %w", err)
	}
	t := tagFromDB(&row)
	return &t, nil
}

// UpdateTag modifies an existing canonical tag.
func (s *Store) UpdateTag(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Tag, error) {
	row, err := s.q.UpdateTag(ctx, db.UpdateTagParams{
		ID:          id,
		Slug:        p.Slug,
		Name:        p.Name,
		ParentID:    p.ParentID,
		Description: p.Description,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("updating tag %s: %w", id, err)
	}
	t := tagFromDB(&row)
	return &t, nil
}

// DeleteTag removes a canonical tag, but only if no aliases reference it.
// The count check provides a good error message; the DB FK constraint (23503)
// is the real safety net against the TOCTOU window between check and delete
// (covers content_tags / content_concepts / concepts and any future references).
func (s *Store) DeleteTag(ctx context.Context, id uuid.UUID) error {
	aliasCount, err := s.q.AliasCountByTagID(ctx, &id)
	if err != nil {
		return fmt.Errorf("counting aliases for tag %s: %w", id, err)
	}
	if aliasCount > 0 {
		return ErrHasReferences
	}
	if err := s.q.DeleteTag(ctx, id); err != nil {
		// FK violation (23503) = race or unchecked reference (e.g. content_tags).
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23503" {
			return ErrHasReferences
		}
		return fmt.Errorf("deleting tag %s: %w", id, err)
	}
	return nil
}

// Aliases returns all tag aliases ordered by creation time.
func (s *Store) Aliases(ctx context.Context) ([]Alias, error) {
	rows, err := s.q.ListAliases(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing aliases: %w", err)
	}
	aliases := make([]Alias, len(rows))
	for i := range rows {
		aliases[i] = aliasFromDB(&rows[i])
	}
	return aliases, nil
}

// UnmappedAliases returns only aliases with no canonical tag mapping.
func (s *Store) UnmappedAliases(ctx context.Context) ([]Alias, error) {
	rows, err := s.q.ListUnmappedAliases(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing unmapped aliases: %w", err)
	}
	aliases := make([]Alias, len(rows))
	for i := range rows {
		aliases[i] = aliasFromDB(&rows[i])
	}
	return aliases, nil
}

// MapAlias maps an alias to a canonical tag.
func (s *Store) MapAlias(ctx context.Context, aliasID, tagID uuid.UUID) (*Alias, error) {
	row, err := s.q.MapAlias(ctx, db.MapAliasParams{
		ID:    aliasID,
		TagID: &tagID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("mapping alias %s: %w", aliasID, err)
	}
	a := aliasFromDB(&row)
	return &a, nil
}

// ConfirmAlias confirms an alias mapping.
func (s *Store) ConfirmAlias(ctx context.Context, id uuid.UUID) (*Alias, error) {
	row, err := s.q.ConfirmAlias(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("confirming alias %s: %w", id, err)
	}
	a := aliasFromDB(&row)
	return &a, nil
}

// RejectAlias rejects an alias — clears tag_id and sets resolution_source to 'rejected'.
func (s *Store) RejectAlias(ctx context.Context, id uuid.UUID) (*Alias, error) {
	row, err := s.q.RejectAlias(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("rejecting alias %s: %w", id, err)
	}
	a := aliasFromDB(&row)
	return &a, nil
}

// DeleteAlias removes an alias. Note: sqlc :exec returns no error for zero rows
// affected, so a delete of a non-existent alias silently succeeds (204).
func (s *Store) DeleteAlias(ctx context.Context, id uuid.UUID) error {
	if err := s.q.DeleteAlias(ctx, id); err != nil {
		return fmt.Errorf("deleting alias %s: %w", id, err)
	}
	return nil
}

// MergeTags merges source tag into target tag.
//
// CALLER CONTRACT: this method performs 7 writes across three junction
// tables plus tag_aliases and tags. Callers that need atomicity MUST
// pass a tx-bound Store via WithTx(tx). Admin HTTP callers use
// ActorMiddleware which supplies the tx via request context; the tag
// handler routes through that path. Without a tx-bound Store, a
// mid-sequence failure leaves the source tag partially detached —
// some junctions moved, some still pointing at source, source row
// not deleted.
//
// Reassigns tag_aliases, content_tags, and bookmark_tags from source
// to target (deduplicating against target's existing rows to avoid
// primary-key collisions on the junctions), then deletes the source
// tag. Without the junction reassignments the final DeleteTag would
// silently cascade every junction row away via ON DELETE CASCADE —
// the data-loss bug this merge is meant to avoid.
func (s *Store) MergeTags(ctx context.Context, sourceID, targetID uuid.UUID) (*MergeResult, error) {
	// Aliases: tag_aliases.tag_id is nullable → queries take *uuid.UUID.
	src := &sourceID
	tgt := &targetID
	if _, err := s.q.DeleteDuplicateAliases(ctx, db.DeleteDuplicateAliasesParams{
		TagID: src, TagID_2: tgt,
	}); err != nil {
		return nil, fmt.Errorf("deleting duplicate aliases: %w", err)
	}
	aliasesMoved, err := s.q.ReassignAliases(ctx, db.ReassignAliasesParams{
		TagID: tgt, TagID_2: src,
	})
	if err != nil {
		return nil, fmt.Errorf("reassigning aliases: %w", err)
	}

	// Content tags: content_tags.tag_id is NOT NULL → non-pointer uuid.UUID.
	if _, err := s.q.DeleteDuplicateContentTags(ctx, db.DeleteDuplicateContentTagsParams{
		TagID: sourceID, TagID_2: targetID,
	}); err != nil {
		return nil, fmt.Errorf("deleting duplicate content tags: %w", err)
	}
	contentTagsMoved, err := s.q.ReassignContentTags(ctx, db.ReassignContentTagsParams{
		TagID: targetID, TagID_2: sourceID,
	})
	if err != nil {
		return nil, fmt.Errorf("reassigning content tags: %w", err)
	}

	// Bookmark tags: same cascade concern as content_tags.
	if _, err := s.q.DeleteDuplicateBookmarkTags(ctx, db.DeleteDuplicateBookmarkTagsParams{
		TagID: sourceID, TagID_2: targetID,
	}); err != nil {
		return nil, fmt.Errorf("deleting duplicate bookmark tags: %w", err)
	}
	bookmarkTagsMoved, err := s.q.ReassignBookmarkTags(ctx, db.ReassignBookmarkTagsParams{
		TagID: targetID, TagID_2: sourceID,
	})
	if err != nil {
		return nil, fmt.Errorf("reassigning bookmark tags: %w", err)
	}

	// Delete the source tag (now has no references)
	if err := s.q.DeleteTag(ctx, sourceID); err != nil {
		return nil, fmt.Errorf("deleting source tag %s: %w", sourceID, err)
	}

	return &MergeResult{
		AliasesMoved:      aliasesMoved,
		ContentTagsMoved:  contentTagsMoved,
		BookmarkTagsMoved: bookmarkTagsMoved,
	}, nil
}

// tagFromDB converts a sqlc-generated db.Tag to the domain Tag.
func tagFromDB(r *db.Tag) Tag {
	return Tag{
		ID:          r.ID,
		Slug:        r.Slug,
		Name:        r.Name,
		ParentID:    r.ParentID,
		Description: r.Description,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// aliasFromDB converts a sqlc-generated db.TagAlias to the domain Alias.
func aliasFromDB(r *db.TagAlias) Alias {
	return Alias{
		ID:               r.ID,
		RawTag:           r.RawTag,
		TagID:            r.TagID,
		ResolutionSource: r.ResolutionSource,
		Confirmed:        r.Confirmed,
		ConfirmedAt:      r.ConfirmedAt,
		CreatedAt:        r.CreatedAt,
	}
}
