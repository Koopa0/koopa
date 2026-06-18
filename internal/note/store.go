// Copyright 2026 Koopa. All rights reserved.

package note

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pgvector/pgvector-go"

	"github.com/Koopa0/koopa/internal/db"
)

// Store handles database operations for notes.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
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

// ConceptRefsForNote returns slug+name resolved concept attachments for a
// single note. Empty slice (never nil) when the note has no attached
// concepts — the HTTP layer serializes this directly.
func (s *Store) ConceptRefsForNote(ctx context.Context, noteID uuid.UUID) ([]ConceptRef, error) {
	rows, err := s.q.ConceptRefsForNote(ctx, noteID)
	if err != nil {
		return nil, fmt.Errorf("loading concept refs for note %s: %w", noteID, err)
	}
	out := make([]ConceptRef, len(rows))
	for i := range rows {
		out[i] = ConceptRef{ID: rows[i].ID, Slug: rows[i].Slug, Name: rows[i].Name}
	}
	return out, nil
}

// TargetRefsForNote returns id+title resolved learning_target attachments
// for a single note.
func (s *Store) TargetRefsForNote(ctx context.Context, noteID uuid.UUID) ([]TargetRef, error) {
	rows, err := s.q.TargetRefsForNote(ctx, noteID)
	if err != nil {
		return nil, fmt.Errorf("loading target refs for note %s: %w", noteID, err)
	}
	out := make([]TargetRef, len(rows))
	for i := range rows {
		out[i] = TargetRef{ID: rows[i].ID, Title: rows[i].Title, Domain: rows[i].Domain}
	}
	return out, nil
}

// Note returns a single note by ID.
func (s *Store) Note(ctx context.Context, id uuid.UUID) (*Note, error) {
	r, err := s.q.NoteByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying note %s: %w", id, err)
	}
	return buildNote(
		r.ID, r.Slug, r.Title, r.Body,
		r.Kind, r.Maturity, r.CreatedBy, r.Metadata,
		r.CreatedAt, r.UpdatedAt,
	)
}

// NoteBySlug returns a single note by slug.
func (s *Store) NoteBySlug(ctx context.Context, slug string) (*Note, error) {
	r, err := s.q.NoteBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying note by slug %q: %w", slug, err)
	}
	return buildNote(
		r.ID, r.Slug, r.Title, r.Body,
		r.Kind, r.Maturity, r.CreatedBy, r.Metadata,
		r.CreatedAt, r.UpdatedAt,
	)
}

// Notes lists notes with optional kind / maturity filters.
func (s *Store) Notes(ctx context.Context, f Filter) ([]Note, int, error) {
	kindArg := nullKind(f.Kind)
	maturityArg := nullMaturity(f.Maturity)

	rows, err := s.q.Notes(ctx, db.NotesParams{
		Limit:     int32(f.PerPage),                // #nosec G115 -- pagination bounded in API layer
		Offset:    int32((f.Page - 1) * f.PerPage), // #nosec G115 -- same
		Kind:      kindArg,
		Maturity:  maturityArg,
		CreatedBy: f.CreatedBy,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing notes: %w", err)
	}

	total, err := s.q.NotesCount(ctx, db.NotesCountParams{
		Kind:      kindArg,
		Maturity:  maturityArg,
		CreatedBy: f.CreatedBy,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("counting notes: %w", err)
	}

	out := make([]Note, 0, len(rows))
	for i := range rows {
		n, convErr := buildNote(
			rows[i].ID, rows[i].Slug, rows[i].Title, rows[i].Body,
			rows[i].Kind, rows[i].Maturity, rows[i].CreatedBy, rows[i].Metadata,
			rows[i].CreatedAt, rows[i].UpdatedAt,
		)
		if convErr != nil {
			return nil, 0, convErr
		}
		out = append(out, *n)
	}
	return out, int(total), nil
}

// Create inserts a new note. Slug uniqueness is enforced by the schema —
// returns ErrConflict on violation. If Kind or Maturity is invalid,
// returns ErrInvalidKind / ErrInvalidMaturity.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Note, error) {
	if !p.Kind.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidKind, p.Kind)
	}
	maturity := p.Maturity
	if maturity == "" {
		maturity = MaturitySeed
	}
	if !maturity.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidMaturity, p.Maturity)
	}

	metaBytes, err := encodeMetadata(p.Metadata)
	if err != nil {
		return nil, err
	}

	r, err := s.q.CreateNote(ctx, db.CreateNoteParams{
		Slug:      p.Slug,
		Title:     p.Title,
		Body:      p.Body,
		Kind:      db.NoteKind(p.Kind),
		Maturity:  db.NoteMaturity(maturity),
		CreatedBy: p.CreatedBy,
		Metadata:  metaBytes,
	})
	if err != nil {
		return nil, mapNoteWriteError(err, "inserting note", fmt.Sprintf("slug=%s", p.Slug))
	}
	return buildNote(
		r.ID, r.Slug, r.Title, r.Body,
		r.Kind, r.Maturity, r.CreatedBy, r.Metadata,
		r.CreatedAt, r.UpdatedAt,
	)
}

// mapNoteWriteError classifies a PostgreSQL note-write failure into a feature
// sentinel. A unique violation (23505) on the slug becomes ErrConflict (with
// conflictDetail appended for context); a check-constraint violation (23514 —
// chk_note_slug_format, chk_note_title_not_blank) becomes ErrInvalidInput; any
// other error is wrapped with operation. Callers handle pgx.ErrNoRows before
// reaching here.
func mapNoteWriteError(err error, operation, conflictDetail string) error {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		return fmt.Errorf("%s: %w", operation, err)
	}
	switch pgErr.Code {
	case pgerrcode.UniqueViolation:
		return fmt.Errorf("%w: %s", ErrConflict, conflictDetail)
	case pgerrcode.CheckViolation:
		return ErrInvalidInput
	default:
		return fmt.Errorf("%s: %w", operation, err)
	}
}

// Update modifies editable fields. Maturity transitions go through
// UpdateMaturity separately.
func (s *Store) Update(ctx context.Context, id uuid.UUID, p UpdateParams) (*Note, error) {
	// Title is optional on update (nil = unchanged), but a present-yet-blank
	// title violates chk_note_title_not_blank. Reject it here so the asymmetry
	// with Create (which requires a non-blank title at the handler boundary)
	// does not let a blank through. The store is the shared write path for both
	// the HTTP handler and the MCP update_note tool, so the check covers both.
	if p.Title != nil && strings.TrimSpace(*p.Title) == "" {
		return nil, ErrInvalidInput
	}
	var kindArg db.NullNoteKind
	if p.Kind != nil {
		if !p.Kind.Valid() {
			return nil, fmt.Errorf("%w: %q", ErrInvalidKind, *p.Kind)
		}
		kindArg = db.NullNoteKind{NoteKind: db.NoteKind(*p.Kind), Valid: true}
	}

	var metaBytes json.RawMessage
	if p.Metadata != nil {
		b, err := encodeMetadata(*p.Metadata)
		if err != nil {
			return nil, err
		}
		metaBytes = b
	}

	r, err := s.q.UpdateNote(ctx, db.UpdateNoteParams{
		ID:       id,
		Slug:     p.Slug,
		Title:    p.Title,
		Body:     p.Body,
		Kind:     kindArg,
		Metadata: metaBytes,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapNoteWriteError(err, fmt.Sprintf("updating note %s", id), "slug")
	}
	n, err := buildNote(
		r.ID, r.Slug, r.Title, r.Body,
		r.Kind, r.Maturity, r.CreatedBy, r.Metadata,
		r.CreatedAt, r.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Reconcile link sets within the caller's tx. A nil pointer leaves the
	// existing links untouched; a non-nil pointer (incl. an empty slice) sets
	// them to exactly the given ids. UpdateNote above already enforced the
	// note exists, so a bad id here is a link error, not a missing note.
	if p.ConceptIDs != nil {
		if err := s.SetConcepts(ctx, id, *p.ConceptIDs); err != nil {
			return nil, err
		}
	}
	if p.TargetIDs != nil {
		if err := s.SetTargets(ctx, id, *p.TargetIDs); err != nil {
			return nil, err
		}
	}
	return n, nil
}

// UpdateMaturity transitions the maturity state. Any transition permitted.
func (s *Store) UpdateMaturity(ctx context.Context, id uuid.UUID, maturity Maturity) (*Note, error) {
	if !maturity.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidMaturity, maturity)
	}
	r, err := s.q.UpdateNoteMaturity(ctx, db.UpdateNoteMaturityParams{
		ID:       id,
		Maturity: db.NoteMaturity(maturity),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating maturity on note %s: %w", id, err)
	}
	return buildNote(
		r.ID, r.Slug, r.Title, r.Body,
		r.Kind, r.Maturity, r.CreatedBy, r.Metadata,
		r.CreatedAt, r.UpdatedAt,
	)
}

// Delete removes a note by ID. Returns ErrNotFound when no row matched.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	n, err := s.q.DeleteNote(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting note %s: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AttachConcept adds a note_concepts row with the given relevance. Idempotent —
// a repeat attach is a no-op (ON CONFLICT DO NOTHING). A concept_id that does
// not exist surfaces as ErrInvalidLink (foreign-key violation), not a 500.
func (s *Store) AttachConcept(ctx context.Context, noteID, conceptID uuid.UUID, relevance string) error {
	if err := s.q.AddNoteConcept(ctx, db.AddNoteConceptParams{
		NoteID:    noteID,
		ConceptID: conceptID,
		Relevance: relevance,
	}); err != nil {
		return linkErr(err, "concept", conceptID, noteID)
	}
	return nil
}

// DetachConcept removes a note_concepts row. Idempotent — deleting a missing row is a no-op.
func (s *Store) DetachConcept(ctx context.Context, noteID, conceptID uuid.UUID) error {
	if err := s.q.DeleteNoteConcept(ctx, db.DeleteNoteConceptParams{
		NoteID:    noteID,
		ConceptID: conceptID,
	}); err != nil {
		return fmt.Errorf("detaching concept %s from note %s: %w", conceptID, noteID, err)
	}
	return nil
}

// ConceptsForNote returns the concept IDs attached to a note.
func (s *Store) ConceptsForNote(ctx context.Context, noteID uuid.UUID) ([]uuid.UUID, error) {
	ids, err := s.q.ConceptsForNote(ctx, noteID)
	if err != nil {
		return nil, fmt.Errorf("listing concepts for note %s: %w", noteID, err)
	}
	return ids, nil
}

// AttachTarget links a note to a learning target. Idempotent — a repeat
// attach is a no-op. A target_id that does not exist surfaces as
// ErrInvalidLink (foreign-key violation), not a 500.
func (s *Store) AttachTarget(ctx context.Context, noteID, targetID uuid.UUID) error {
	if err := s.q.AddNoteTarget(ctx, db.AddNoteTargetParams{
		NoteID:   noteID,
		TargetID: targetID,
	}); err != nil {
		return linkErr(err, "target", targetID, noteID)
	}
	return nil
}

// DetachTarget removes a learning_target_notes row. Idempotent — deleting a
// missing row is a no-op.
func (s *Store) DetachTarget(ctx context.Context, noteID, targetID uuid.UUID) error {
	if err := s.q.DeleteNoteTarget(ctx, db.DeleteNoteTargetParams{
		NoteID:   noteID,
		TargetID: targetID,
	}); err != nil {
		return fmt.Errorf("detaching target %s from note %s: %w", targetID, noteID, err)
	}
	return nil
}

// TargetsForNote returns the learning_target IDs linked to a note.
func (s *Store) TargetsForNote(ctx context.Context, noteID uuid.UUID) ([]uuid.UUID, error) {
	ids, err := s.q.TargetsForNote(ctx, noteID)
	if err != nil {
		return nil, fmt.Errorf("listing targets for note %s: %w", noteID, err)
	}
	return ids, nil
}

// SetConcepts reconciles a note's concept links to exactly want. Concepts in
// want but not yet linked are attached with 'secondary' relevance (primary
// designation is a separate admin action); links absent from want are
// detached. Existing links are left untouched, so a primary set elsewhere
// survives a re-save. Idempotent and order-independent. Runs on the caller's
// store binding, so when invoked through a tx-bound Store the whole reconcile
// commits or rolls back atomically with the surrounding request.
func (s *Store) SetConcepts(ctx context.Context, noteID uuid.UUID, want []uuid.UUID) error {
	current, err := s.ConceptsForNote(ctx, noteID)
	if err != nil {
		return err
	}
	add, remove := diffIDs(current, want)
	for _, id := range add {
		if err := s.AttachConcept(ctx, noteID, id, "secondary"); err != nil {
			return err
		}
	}
	for _, id := range remove {
		if err := s.DetachConcept(ctx, noteID, id); err != nil {
			return err
		}
	}
	return nil
}

// SetTargets reconciles a note's learning-target links to exactly want.
// Mirrors SetConcepts.
func (s *Store) SetTargets(ctx context.Context, noteID uuid.UUID, want []uuid.UUID) error {
	current, err := s.TargetsForNote(ctx, noteID)
	if err != nil {
		return err
	}
	add, remove := diffIDs(current, want)
	for _, id := range add {
		if err := s.AttachTarget(ctx, noteID, id); err != nil {
			return err
		}
	}
	for _, id := range remove {
		if err := s.DetachTarget(ctx, noteID, id); err != nil {
			return err
		}
	}
	return nil
}

// diffIDs returns the ids to add (present in want, absent from current) and
// to remove (present in current, absent from want), treating both as sets.
// want is de-duplicated; add preserves want's order, remove preserves
// current's order.
func diffIDs(current, want []uuid.UUID) (add, remove []uuid.UUID) {
	curSet := make(map[uuid.UUID]struct{}, len(current))
	for _, id := range current {
		curSet[id] = struct{}{}
	}
	wantSet := make(map[uuid.UUID]struct{}, len(want))
	for _, id := range want {
		if _, dup := wantSet[id]; dup {
			continue
		}
		wantSet[id] = struct{}{}
		if _, ok := curSet[id]; !ok {
			add = append(add, id)
		}
	}
	for _, id := range current {
		if _, ok := wantSet[id]; !ok {
			remove = append(remove, id)
		}
	}
	return add, remove
}

// linkErr maps a junction-write failure to a sentinel. A foreign-key
// violation means the referenced concept / target id does not exist, which
// is caller input error (ErrInvalidLink → 422), not an internal fault.
func linkErr(err error, kind string, id, noteID uuid.UUID) error {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.ForeignKeyViolation {
		return fmt.Errorf("%w: %s %s", ErrInvalidLink, kind, id)
	}
	return fmt.Errorf("attaching %s %s to note %s: %w", kind, id, noteID, err)
}

// Search performs a full-text search over notes (title + body). Returns
// results ordered by relevance, capped by limit. Empty query returns no
// results — the caller is responsible for query validation.
func (s *Store) Search(ctx context.Context, query string, limit int) ([]Note, error) {
	if query == "" {
		return nil, nil
	}
	rows, err := s.q.SearchNotes(ctx, db.SearchNotesParams{
		Query:      query,
		MaxResults: int32(limit), // #nosec G115 -- limit bounded by MCP handler
	})
	if err != nil {
		return nil, fmt.Errorf("searching notes: %w", err)
	}
	out := make([]Note, 0, len(rows))
	for i := range rows {
		n, convErr := buildNote(
			rows[i].ID, rows[i].Slug, rows[i].Title, rows[i].Body,
			rows[i].Kind, rows[i].Maturity, rows[i].CreatedBy, rows[i].Metadata,
			rows[i].CreatedAt, rows[i].UpdatedAt,
		)
		if convErr != nil {
			return nil, convErr
		}
		out = append(out, *n)
	}
	return out, nil
}

// SemanticSearch returns notes ranked by cosine similarity to the query
// embedding — the vector counterpart of Search, with the same visibility
// (every note, archived included). Notes without embeddings are skipped.
// Used by search_knowledge to feed the hybrid RRF merge.
func (s *Store) SemanticSearch(ctx context.Context, queryEmbedding pgvector.Vector, limit int) ([]Note, error) {
	rows, err := s.q.InternalSemanticSearchNotes(ctx, db.InternalSemanticSearchNotesParams{
		TargetEmbedding: queryEmbedding,
		MaxResults:      int32(limit), // #nosec G115 -- limit bounded by MCP handler
	})
	if err != nil {
		return nil, fmt.Errorf("semantic searching notes: %w", err)
	}
	out := make([]Note, 0, len(rows))
	for i := range rows {
		n, convErr := buildNote(
			rows[i].ID, rows[i].Slug, rows[i].Title, rows[i].Body,
			rows[i].Kind, rows[i].Maturity, rows[i].CreatedBy, rows[i].Metadata,
			rows[i].CreatedAt, rows[i].UpdatedAt,
		)
		if convErr != nil {
			return nil, convErr
		}
		out = append(out, *n)
	}
	return out, nil
}

// buildNote is the common conversion from the flat tuple of row fields (sqlc
// generates a distinct row type per query, all with the same fields) into the
// domain Note type.
func buildNote(
	id uuid.UUID,
	slug, title, body string,
	kind db.NoteKind,
	maturity db.NoteMaturity,
	createdBy string,
	rawMeta json.RawMessage,
	createdAt, updatedAt time.Time,
) (*Note, error) {
	var meta map[string]any
	if len(rawMeta) > 0 {
		if err := json.Unmarshal(rawMeta, &meta); err != nil {
			return nil, fmt.Errorf("unmarshaling note %s metadata: %w", id, err)
		}
	}
	return &Note{
		ID:        id,
		Slug:      slug,
		Title:     title,
		Body:      body,
		Kind:      Kind(kind),
		Maturity:  Maturity(maturity),
		CreatedBy: createdBy,
		Metadata:  meta,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, nil
}

// nullKind wraps an optional note.Kind into db.NullNoteKind.
func nullKind(k *Kind) db.NullNoteKind {
	if k == nil {
		return db.NullNoteKind{}
	}
	return db.NullNoteKind{NoteKind: db.NoteKind(*k), Valid: true}
}

// nullMaturity wraps an optional note.Maturity into db.NullNoteMaturity.
func nullMaturity(m *Maturity) db.NullNoteMaturity {
	if m == nil {
		return db.NullNoteMaturity{}
	}
	return db.NullNoteMaturity{NoteMaturity: db.NoteMaturity(*m), Valid: true}
}

// encodeMetadata marshals a metadata map to json.RawMessage. Nil → nil.
func encodeMetadata(m map[string]any) (json.RawMessage, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshaling note metadata: %w", err)
	}
	return b, nil
}
