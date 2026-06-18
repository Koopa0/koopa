// Copyright 2026 Koopa. All rights reserved.

package song

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

// Store handles database operations for songs and their reflections.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by the admin
// handlers via api.ActorMiddleware's per-request tx. No audit triggers fire
// on the song tables, but mutations still run inside the request tx so
// multi-statement handlers stay atomic.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// Song returns a single song by ID.
func (s *Store) Song(ctx context.Context, id uuid.UUID) (*Song, error) {
	r, err := s.q.SongByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying song %s: %w", id, err)
	}
	return buildSong(&r), nil
}

// Songs lists the shelf, ordered by most recently updated. The whole shelf
// is ヨルシカ, so there is no artist filter; album grouping is the frontend's
// concern.
func (s *Store) Songs(ctx context.Context) ([]Song, error) {
	rows, err := s.q.Songs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing songs: %w", err)
	}
	out := make([]Song, len(rows))
	for i := range rows {
		out[i] = *buildSong(&rows[i])
	}
	return out, nil
}

// Create inserts a new song. The study fields default to empty for the owner
// to fill later. p is passed by pointer per the store convention; the store
// neither retains nor mutates it, so the caller keeps ownership.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Song, error) {
	r, err := s.q.CreateSong(ctx, db.CreateSongParams{
		TitleJa:     p.Title,
		Album:       p.Album,
		LyricsJa:    p.LyricsJa,
		Translation: p.Translation,
		Vocabulary:  p.Vocabulary,
	})
	if err != nil {
		return nil, fmt.Errorf("inserting song: %w", err)
	}
	return buildSong(&r), nil
}

// Update modifies editable fields; nil params stay unchanged.
func (s *Store) Update(ctx context.Context, id uuid.UUID, p UpdateParams) (*Song, error) {
	r, err := s.q.UpdateSong(ctx, db.UpdateSongParams{
		ID:          id,
		TitleJa:     p.Title,
		Album:       p.Album,
		LyricsJa:    p.LyricsJa,
		Translation: p.Translation,
		Vocabulary:  p.Vocabulary,
		IsPublic:    p.IsPublic,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating song %s: %w", id, err)
	}
	return buildSong(&r), nil
}

// Delete removes a song by ID. ON DELETE CASCADE removes the song's entire
// reflection thread with it. Returns ErrNotFound when no row matched.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	n, err := s.q.DeleteSong(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting song %s: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Reflections returns the diary thread for one song: entry_date ascending,
// created_at as the same-day tiebreak.
func (s *Store) Reflections(ctx context.Context, songID uuid.UUID) ([]Reflection, error) {
	rows, err := s.q.ReflectionsForSong(ctx, songID)
	if err != nil {
		return nil, fmt.Errorf("listing reflections for song %s: %w", songID, err)
	}
	out := make([]Reflection, len(rows))
	for i := range rows {
		out[i] = buildReflection(&rows[i])
	}
	return out, nil
}

// CreateReflection inserts a diary entry under a song. A nil entryDate
// defaults to today (the database's CURRENT_DATE). A missing parent song
// surfaces as ErrNotFound (FK violation).
func (s *Store) CreateReflection(ctx context.Context, songID uuid.UUID, entryDate *time.Time, body string) (*Reflection, error) {
	r, err := s.q.CreateSongReflection(ctx, db.CreateSongReflectionParams{
		SongID:    songID,
		EntryDate: entryDate,
		Body:      body,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.ForeignKeyViolation {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("inserting reflection under song %s: %w", songID, err)
	}
	out := buildReflection(&r)
	return &out, nil
}

// UpdateReflection modifies a diary entry, bound to its parent song in the
// WHERE clause — a {songID, id} mismatch is ErrNotFound, never a cross-song
// write.
func (s *Store) UpdateReflection(ctx context.Context, songID, id uuid.UUID, p UpdateReflectionParams) (*Reflection, error) {
	r, err := s.q.UpdateSongReflection(ctx, db.UpdateSongReflectionParams{
		ID:        id,
		SongID:    songID,
		Body:      p.Body,
		EntryDate: p.EntryDate,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating reflection %s under song %s: %w", id, songID, err)
	}
	out := buildReflection(&r)
	return &out, nil
}

// DeleteReflection removes a diary entry with the same membership binding as
// UpdateReflection. Returns ErrNotFound when no row matched.
func (s *Store) DeleteReflection(ctx context.Context, songID, id uuid.UUID) error {
	n, err := s.q.DeleteSongReflection(ctx, db.DeleteSongReflectionParams{
		ID:     id,
		SongID: songID,
	})
	if err != nil {
		return fmt.Errorf("deleting reflection %s under song %s: %w", id, songID, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// buildSong converts the sqlc row into the domain type.
func buildSong(r *db.Song) *Song {
	return &Song{
		ID:          r.ID,
		TitleJa:     r.TitleJa,
		Album:       r.Album,
		LyricsJa:    r.LyricsJa,
		Translation: r.Translation,
		Vocabulary:  r.Vocabulary,
		IsPublic:    r.IsPublic,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// buildReflection converts the sqlc row into the domain type.
func buildReflection(r *db.SongReflection) Reflection {
	return Reflection{
		ID:        r.ID,
		SongID:    r.SongID,
		EntryDate: r.EntryDate,
		Body:      r.Body,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}
