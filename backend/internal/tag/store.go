package tag

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store manages tag normalization and note-tag associations.
type Store struct {
	q *db.Queries
}

// NewStore returns a tag Store backed by the given connection (pool or tx).
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a new Store that uses the given transaction.
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
		return Resolved{RawTag: rawTag, TagID: nil, MatchMethod: "unmapped"}
	}
	// Step 0: if admin has rejected this raw tag, skip all resolution steps.
	rejected, err := s.q.IsAliasRejected(ctx, rawTag)
	if err == nil && rejected {
		return Resolved{RawTag: rawTag, TagID: nil, MatchMethod: "unmapped"}
	}

	// Step 1: exact alias match
	alias, err := s.q.AliasByExactRawTag(ctx, rawTag)
	if err == nil && alias.TagID != nil {
		return Resolved{RawTag: rawTag, TagID: alias.TagID, MatchMethod: "exact"}
	}

	// Step 2: case-insensitive alias match
	alias, err = s.q.AliasByCaseInsensitiveRawTag(ctx, rawTag)
	if err == nil && alias.TagID != nil {
		// Auto-create exact alias for future lookups
		_ = s.q.InsertAliasWithTag(ctx, db.InsertAliasWithTagParams{
			RawTag:      rawTag,
			TagID:       alias.TagID,
			MatchMethod: "case_insensitive",
		}) // best-effort
		return Resolved{RawTag: rawTag, TagID: alias.TagID, MatchMethod: "case_insensitive"}
	}

	// Step 3: slug match against canonical tags
	slug := Slugify(rawTag)
	if slug != "" {
		t, err := s.q.TagBySlug(ctx, slug)
		if err == nil {
			tagID := t.ID
			// Auto-create alias for future lookups
			_ = s.q.InsertAliasWithTag(ctx, db.InsertAliasWithTagParams{
				RawTag:      rawTag,
				TagID:       &tagID,
				MatchMethod: "slug",
			}) // best-effort
			return Resolved{RawTag: rawTag, TagID: &tagID, MatchMethod: "slug"}
		}
	}

	// Step 4: unmapped — insert alias with NULL tag_id for admin review
	_ = s.q.InsertUnmappedAlias(ctx, rawTag) // best-effort, ON CONFLICT DO NOTHING
	return Resolved{RawTag: rawTag, TagID: nil, MatchMethod: "unmapped"}
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
			results = append(results, Resolved{RawTag: raw, TagID: tagID, MatchMethod: "exact"})
			continue
		}
		// Not in batch result — run the full 4-step pipeline for this tag only.
		results = append(results, s.ResolveTag(ctx, raw))
	}
	return results
}

// SyncNoteTags replaces all tag associations for a note with the given tag IDs.
// Uses delete-then-insert for simplicity (junction table has no extra columns).
// Must be called within the same transaction as UpsertNote for atomicity.
func (s *Store) SyncNoteTags(ctx context.Context, noteID int64, tagIDs []uuid.UUID) error {
	if err := s.q.DeleteNoteTagsByNoteID(ctx, noteID); err != nil {
		return fmt.Errorf("deleting note tags for note %d: %w", noteID, err)
	}
	if len(tagIDs) == 0 {
		return nil
	}
	if err := s.q.InsertNoteTags(ctx, db.InsertNoteTagsParams{
		NoteID: noteID,
		TagIds: tagIDs,
	}); err != nil {
		return fmt.Errorf("inserting note tags for note %d: %w", noteID, err)
	}
	return nil
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
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
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
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("updating tag %s: %w", id, err)
	}
	t := tagFromDB(&row)
	return &t, nil
}

// DeleteTag removes a canonical tag, but only if no aliases or notes reference it.
// The count checks provide a good error message; the DB FK constraint (23503)
// is the real safety net against the TOCTOU window between check and delete.
func (s *Store) DeleteTag(ctx context.Context, id uuid.UUID) error {
	aliasCount, err := s.q.AliasCountByTagID(ctx, &id)
	if err != nil {
		return fmt.Errorf("counting aliases for tag %s: %w", id, err)
	}
	noteCount, err := s.q.NoteTagCountByTagID(ctx, id)
	if err != nil {
		return fmt.Errorf("counting note tags for tag %s: %w", id, err)
	}
	if aliasCount > 0 || noteCount > 0 {
		return ErrHasReferences
	}
	if err := s.q.DeleteTag(ctx, id); err != nil {
		// FK violation (23503) = race: reference inserted between count check and delete.
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

// RejectAlias rejects an alias — clears tag_id and sets match_method to 'rejected'.
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

// BackfillNoteTags scans all obsidian_notes with raw tags JSONB,
// resolves each through the 4-step normalization pipeline,
// and writes resolved tag IDs to obsidian_note_tags.
// Additive only — existing junction rows are preserved (ON CONFLICT DO NOTHING).
func (s *Store) BackfillNoteTags(ctx context.Context) (*BackfillResult, error) {
	rows, err := s.q.NotesWithRawTags(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying notes with raw tags: %w", err)
	}

	result := &BackfillResult{}
	for _, row := range rows {
		var rawTags []string
		if err := json.Unmarshal(row.Tags, &rawTags); err != nil {
			continue // skip notes with malformed tags JSONB
		}
		if len(rawTags) == 0 {
			continue
		}

		result.NotesProcessed++
		resolved := s.ResolveTags(ctx, rawTags)
		var mappedIDs []uuid.UUID
		for _, r := range resolved {
			if r.TagID != nil {
				result.TagsMapped++
				mappedIDs = append(mappedIDs, *r.TagID)
			} else {
				result.TagsUnmapped++
			}
		}
		if len(mappedIDs) > 0 {
			_ = s.q.InsertNoteTags(ctx, db.InsertNoteTagsParams{
				NoteID: row.ID,
				TagIds: mappedIDs,
			}) // best-effort, ON CONFLICT DO NOTHING
		}
	}
	return result, nil
}

// MergeTags merges source tag into target tag within a transaction.
// Reassigns all aliases, note-tags, and event-tags, then deletes the source tag.
func (s *Store) MergeTags(ctx context.Context, tx pgx.Tx, sourceID, targetID uuid.UUID) (*MergeResult, error) {
	txQ := s.q.WithTx(tx)

	// Delete duplicate aliases then reassign (tag_aliases.tag_id is nullable → *uuid.UUID)
	src := &sourceID
	tgt := &targetID
	if _, err := txQ.DeleteDuplicateAliases(ctx, db.DeleteDuplicateAliasesParams{
		TagID: src, TagID_2: tgt,
	}); err != nil {
		return nil, fmt.Errorf("deleting duplicate aliases: %w", err)
	}
	aliasesMoved, err := txQ.ReassignAliases(ctx, db.ReassignAliasesParams{
		TagID: tgt, TagID_2: src,
	})
	if err != nil {
		return nil, fmt.Errorf("reassigning aliases: %w", err)
	}

	// Delete duplicate note-tags then reassign (junction tag_id is NOT NULL → uuid.UUID)
	if _, delNoteErr := txQ.DeleteDuplicateNoteTags(ctx, db.DeleteDuplicateNoteTagsParams{
		TagID: sourceID, TagID_2: targetID,
	}); delNoteErr != nil {
		return nil, fmt.Errorf("deleting duplicate note tags: %w", delNoteErr)
	}
	notesMoved, err := txQ.ReassignNoteTags(ctx, db.ReassignNoteTagsParams{
		TagID: targetID, TagID_2: sourceID,
	})
	if err != nil {
		return nil, fmt.Errorf("reassigning note tags: %w", err)
	}

	// Delete duplicate event-tags then reassign
	if _, delEventErr := txQ.DeleteDuplicateEventTags(ctx, db.DeleteDuplicateEventTagsParams{
		TagID: sourceID, TagID_2: targetID,
	}); delEventErr != nil {
		return nil, fmt.Errorf("deleting duplicate event tags: %w", delEventErr)
	}
	eventsMoved, err := txQ.ReassignEventTags(ctx, db.ReassignEventTagsParams{
		TagID: targetID, TagID_2: sourceID,
	})
	if err != nil {
		return nil, fmt.Errorf("reassigning event tags: %w", err)
	}

	// Delete the source tag (now has no references)
	if err := txQ.DeleteTag(ctx, sourceID); err != nil {
		return nil, fmt.Errorf("deleting source tag %s: %w", sourceID, err)
	}

	return &MergeResult{
		AliasesMoved: aliasesMoved,
		NotesMoved:   notesMoved,
		EventsMoved:  eventsMoved,
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
		ID:          r.ID,
		RawTag:      r.RawTag,
		TagID:       r.TagID,
		MatchMethod: r.MatchMethod,
		Confirmed:   r.Confirmed,
		ConfirmedAt: r.ConfirmedAt,
		CreatedAt:   r.CreatedAt,
	}
}
