package note

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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
		Limit:    int32(f.PerPage),                // #nosec G115 -- pagination bounded in API layer
		Offset:   int32((f.Page - 1) * f.PerPage), // #nosec G115 -- same
		Kind:     kindArg,
		Maturity: maturityArg,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing notes: %w", err)
	}

	total, err := s.q.NotesCount(ctx, db.NotesCountParams{
		Kind:     kindArg,
		Maturity: maturityArg,
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
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, fmt.Errorf("%w: slug=%s", ErrConflict, p.Slug)
		}
		return nil, fmt.Errorf("inserting note: %w", err)
	}
	return buildNote(
		r.ID, r.Slug, r.Title, r.Body,
		r.Kind, r.Maturity, r.CreatedBy, r.Metadata,
		r.CreatedAt, r.UpdatedAt,
	)
}

// Update modifies editable fields. Maturity transitions go through
// UpdateMaturity separately.
func (s *Store) Update(ctx context.Context, id uuid.UUID, p UpdateParams) (*Note, error) {
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
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, fmt.Errorf("%w: slug", ErrConflict)
		}
		return nil, fmt.Errorf("updating note %s: %w", id, err)
	}
	return buildNote(
		r.ID, r.Slug, r.Title, r.Body,
		r.Kind, r.Maturity, r.CreatedBy, r.Metadata,
		r.CreatedAt, r.UpdatedAt,
	)
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
// a repeat attach is a no-op. At most one primary per note is enforced by
// idx_note_concepts_one_primary; a second primary attach will raise an FK
// conflict that bubbles up as a DB error.
func (s *Store) AttachConcept(ctx context.Context, noteID, conceptID uuid.UUID, relevance string) error {
	if err := s.q.AddNoteConcept(ctx, db.AddNoteConceptParams{
		NoteID:    noteID,
		ConceptID: conceptID,
		Relevance: relevance,
	}); err != nil {
		return fmt.Errorf("attaching concept %s to note %s: %w", conceptID, noteID, err)
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
