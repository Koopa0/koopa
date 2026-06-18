// Copyright 2026 Koopa. All rights reserved.

// store.go holds the Store for tags + tag_aliases, including:
//
//   - ResolveTag / ResolveTags — the normalization pipeline: admin-rejected
//     raw tags are skipped, then exact alias → case-insensitive alias →
//     slug → unmapped. New mappings are inserted best-effort so the next
//     lookup is O(1). ResolveTags batches every step.
//   - MergeTags — the manual tag-consolidation path. Every step is
//     explicit and transactional because the ON DELETE CASCADE on
//     the junction tables would silently wipe history if the merge
//     hit DeleteTag without first reassigning aliases / content_tags.
//     Do NOT simplify this to a single DELETE —
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
	"maps"
	"slices"
	"strings"

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

// ResolveTags normalizes a slice of raw tags through the same pipeline as
// ResolveTag, but batches every step so the cost is a fixed number of queries
// regardless of how many tags miss the exact-match fast path. Results are
// positionally aligned with rawTags (duplicates included). Resolution sources
// match ResolveTag: auto-exact, auto-ci, auto-slug, or unmapped.
func (s *Store) ResolveTags(ctx context.Context, rawTags []string) []Resolved {
	if len(rawTags) == 0 {
		return nil
	}

	r := newTagResolution(rawTags)
	r.markOversized()

	// On batch exact-match failure, fall back to per-tag resolution for the
	// remainder — faithful to the single-tag path.
	if !s.resolveExact(ctx, r) {
		for i, raw := range rawTags {
			if !r.done[i] {
				r.results[i] = s.ResolveTag(ctx, raw)
			}
		}
		return r.results
	}

	s.markRejected(ctx, r)
	s.resolveCaseInsensitive(ctx, r)
	s.resolveSlug(ctx, r)
	s.memoize(ctx, r)
	s.markRemainingUnmapped(ctx, r)
	return r.results
}

// tagResolution accumulates the positionally-aligned results of a batched
// ResolveTags pass plus the buffer of ci/slug matches awaiting memoization.
type tagResolution struct {
	raw     []string
	results []Resolved
	done    []bool

	memoRaw []string
	memoTag []uuid.UUID
	memoSrc []string
}

func newTagResolution(rawTags []string) *tagResolution {
	return &tagResolution{
		raw:     rawTags,
		results: make([]Resolved, len(rawTags)),
		done:    make([]bool, len(rawTags)),
	}
}

// mapped fills slot i with a resolved tag.
func (r *tagResolution) mapped(i int, tagID *uuid.UUID, source string) {
	r.results[i] = Resolved{RawTag: r.raw[i], TagID: tagID, ResolutionSource: source}
	r.done[i] = true
}

// markUnmapped fills slot i as unmapped.
func (r *tagResolution) markUnmapped(i int) {
	r.results[i] = Resolved{RawTag: r.raw[i], TagID: nil, ResolutionSource: "unmapped"}
	r.done[i] = true
}

// memo queues a ci/slug match to be written back as an exact alias.
func (r *tagResolution) memo(raw string, tagID uuid.UUID, source string) {
	r.memoRaw = append(r.memoRaw, raw)
	r.memoTag = append(r.memoTag, tagID)
	r.memoSrc = append(r.memoSrc, source)
}

// remaining returns the raw tags whose slot is not yet filled (order preserved).
func (r *tagResolution) remaining() []string {
	out := make([]string, 0, len(r.raw))
	for i, raw := range r.raw {
		if !r.done[i] {
			out = append(out, raw)
		}
	}
	return out
}

// markOversized drops hostile oversized tags to unmapped, never written.
func (r *tagResolution) markOversized() {
	for i, raw := range r.raw {
		if len(raw) > maxRawTagLen {
			r.markUnmapped(i)
		}
	}
}

// resolveExact fills exact alias matches. Returns false if the batch query
// failed, signalling the caller to fall back to per-tag resolution.
func (s *Store) resolveExact(ctx context.Context, r *tagResolution) bool {
	exact, err := s.q.AliasesByExactRawTags(ctx, r.remaining())
	if err != nil {
		return false
	}
	byRaw := make(map[string]*uuid.UUID, len(exact))
	for _, a := range exact {
		byRaw[a.RawTag] = a.TagID
	}
	for i, raw := range r.raw {
		if r.done[i] {
			continue
		}
		if tagID, ok := byRaw[raw]; ok {
			r.mapped(i, tagID, "auto-exact")
		}
	}
	return true
}

// markRejected drops admin-rejected raw tags to unmapped before ci/slug so a
// rejected tag can never re-map. Query errors are swallowed (treated as none
// rejected), matching the single-tag path's leniency.
func (s *Store) markRejected(ctx context.Context, r *tagResolution) {
	rejected, err := s.q.RejectedRawTags(ctx, r.remaining())
	if err != nil || len(rejected) == 0 {
		return
	}
	set := make(map[string]struct{}, len(rejected))
	for _, raw := range rejected {
		set[raw] = struct{}{}
	}
	for i, raw := range r.raw {
		if r.done[i] {
			continue
		}
		if _, ok := set[raw]; ok {
			r.markUnmapped(i)
		}
	}
}

// resolveCaseInsensitive fills case-insensitive alias matches (keyed by
// lower-cased raw_tag) and queues them for memoization. Errors are swallowed.
func (s *Store) resolveCaseInsensitive(ctx context.Context, r *tagResolution) {
	ci, err := s.q.AliasesByCaseInsensitiveRawTags(ctx, r.remaining())
	if err != nil || len(ci) == 0 {
		return
	}
	byLower := make(map[string]*uuid.UUID, len(ci))
	for _, a := range ci {
		byLower[strings.ToLower(a.RawTag)] = a.TagID
	}
	for i, raw := range r.raw {
		if r.done[i] {
			continue
		}
		if tagID, ok := byLower[strings.ToLower(raw)]; ok && tagID != nil {
			r.mapped(i, tagID, "auto-ci")
			r.memo(raw, *tagID, "auto-ci")
		}
	}
}

// resolveSlug fills slug matches against canonical tags and queues them for
// memoization. Errors are swallowed.
func (s *Store) resolveSlug(ctx context.Context, r *tagResolution) {
	slugByIndex := make(map[int]string)
	slugSet := make(map[string]struct{})
	for i, raw := range r.raw {
		if r.done[i] {
			continue
		}
		if slug := Slugify(raw); slug != "" {
			slugByIndex[i] = slug
			slugSet[slug] = struct{}{}
		}
	}
	if len(slugSet) == 0 {
		return
	}
	tags, err := s.q.TagsBySlugs(ctx, slices.Sorted(maps.Keys(slugSet)))
	if err != nil || len(tags) == 0 {
		return
	}
	idBySlug := make(map[string]uuid.UUID, len(tags))
	for i := range tags {
		idBySlug[tags[i].Slug] = tags[i].ID
	}
	for i := range r.raw {
		if r.done[i] {
			continue
		}
		slug, ok := slugByIndex[i]
		if !ok {
			continue
		}
		if id, ok := idBySlug[slug]; ok {
			tagID := id
			r.mapped(i, &tagID, "auto-slug")
			r.memo(r.raw[i], tagID, "auto-slug")
		}
	}
}

// memoize best-effort records ci/slug matches as exact aliases for next time.
func (s *Store) memoize(ctx context.Context, r *tagResolution) {
	if len(r.memoRaw) == 0 {
		return
	}
	_ = s.q.InsertResolvedAliases(ctx, db.InsertResolvedAliasesParams{
		RawTags: r.memoRaw,
		TagIds:  r.memoTag,
		Sources: r.memoSrc,
	}) // best-effort
}

// markRemainingUnmapped records still-unresolved raw tags for admin review.
func (s *Store) markRemainingUnmapped(ctx context.Context, r *tagResolution) {
	rest := r.remaining()
	if len(rest) == 0 {
		return
	}
	_ = s.q.InsertUnmappedAliases(ctx, rest) // best-effort
	for i := range r.raw {
		if !r.done[i] {
			r.markUnmapped(i)
		}
	}
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
// CALLER CONTRACT: this method performs 5 writes across two junction
// tables (tag_aliases, content_tags) plus the source tags row. Callers
// that need atomicity MUST pass a tx-bound Store via WithTx(tx). Admin
// HTTP callers use ActorMiddleware which supplies the tx via request
// context; the tag handler routes through that path. Without a tx-bound
// Store, a mid-sequence failure leaves the source tag partially detached
// — some junctions moved, some still pointing at source, source row not
// deleted.
//
// Reassigns tag_aliases and content_tags from source to target
// (deduplicating against target's existing rows to avoid primary-key
// collisions on the junctions), then deletes the source tag. Without the
// junction reassignments the final DeleteTag would silently cascade every
// junction row away via ON DELETE CASCADE — the data-loss bug this merge
// is meant to avoid.
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

	// Delete the source tag (now has no references)
	if err := s.q.DeleteTag(ctx, sourceID); err != nil {
		return nil, fmt.Errorf("deleting source tag %s: %w", sourceID, err)
	}

	return &MergeResult{
		AliasesMoved:     aliasesMoved,
		ContentTagsMoved: contentTagsMoved,
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
