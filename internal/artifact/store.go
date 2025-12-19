package artifact

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/koopa0/koopa-cli/internal/sqlc"
)

// Store manages artifact persistence with PostgreSQL backend.
// Design follows Google ADK-go artifact.Service pattern.
//
// Each artifact is identified by (SessionID, Filename).
// Filename must be unique within a session.
type Store struct {
	queries *sqlc.Queries
	logger  *slog.Logger
}

// New creates a new Store instance.
//
// Parameters:
//   - queries: sqlc generated queries
//   - logger: Logger for debugging (nil = use default)
func New(queries *sqlc.Queries, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{
		queries: queries,
		logger:  logger,
	}
}

// Save creates or updates an artifact.
// If (sessionID, filename) exists, updates the content and increments version.
// If not, creates a new artifact.
func (s *Store) Save(ctx context.Context, a *Artifact) error {
	if err := ValidateFilename(a.Filename); err != nil {
		return err
	}

	var messageID pgtype.UUID
	if a.MessageID != nil {
		messageID = pgtype.UUID{Bytes: *a.MessageID, Valid: true}
	}

	var language *string
	if a.Language != "" {
		language = &a.Language
	}

	row, err := s.queries.SaveArtifact(ctx, sqlc.SaveArtifactParams{
		SessionID: pgtype.UUID{Bytes: a.SessionID, Valid: true},
		MessageID: messageID,
		Filename:  a.Filename,
		Type:      string(a.Type),
		Language:  language,
		Title:     a.Title,
		Content:   a.Content,
	})
	if err != nil {
		return fmt.Errorf("save artifact %s: %w", a.Filename, err)
	}

	// Update artifact with returned values
	a.ID = pgUUIDToUUID(row.ID)
	a.Version = int(row.Version)
	a.SequenceNumber = int(row.SequenceNumber)
	a.CreatedAt = row.CreatedAt.Time
	a.UpdatedAt = row.UpdatedAt.Time

	s.logger.Debug("saved artifact",
		"session_id", a.SessionID,
		"filename", a.Filename,
		"version", a.Version)
	return nil
}

// Get retrieves an artifact by session and filename.
// Returns ErrNotFound if the artifact does not exist.
func (s *Store) Get(ctx context.Context, sessionID uuid.UUID, filename string) (*Artifact, error) {
	if err := ValidateFilename(filename); err != nil {
		return nil, err
	}

	row, err := s.queries.GetArtifactByFilename(ctx, sqlc.GetArtifactByFilenameParams{
		SessionID: pgtype.UUID{Bytes: sessionID, Valid: true},
		Filename:  filename,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get artifact %s: %w", filename, err)
	}

	return sqlcArtifactToArtifact(row), nil
}

// List returns all artifact filenames for a session.
func (s *Store) List(ctx context.Context, sessionID uuid.UUID) ([]string, error) {
	filenames, err := s.queries.ListArtifactFilenames(ctx,
		pgtype.UUID{Bytes: sessionID, Valid: true},
	)
	if err != nil {
		return nil, fmt.Errorf("list artifacts for session %s: %w", sessionID, err)
	}
	return filenames, nil
}

// Delete removes an artifact by session and filename.
// Returns ErrNotFound if the artifact does not exist.
func (s *Store) Delete(ctx context.Context, sessionID uuid.UUID, filename string) error {
	if err := ValidateFilename(filename); err != nil {
		return err
	}

	rowsAffected, err := s.queries.DeleteArtifactByFilename(ctx, sqlc.DeleteArtifactByFilenameParams{
		SessionID: pgtype.UUID{Bytes: sessionID, Valid: true},
		Filename:  filename,
	})
	if err != nil {
		return fmt.Errorf("delete artifact %s: %w", filename, err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	s.logger.Debug("deleted artifact",
		"session_id", sessionID,
		"filename", filename)
	return nil
}

// DeleteBySession removes all artifacts for a session.
// This is called when the parent session is deleted.
func (s *Store) DeleteBySession(ctx context.Context, sessionID uuid.UUID) error {
	if err := s.queries.DeleteArtifactsBySession(ctx,
		pgtype.UUID{Bytes: sessionID, Valid: true},
	); err != nil {
		return fmt.Errorf("delete artifacts for session %s: %w", sessionID, err)
	}

	s.logger.Debug("deleted artifacts by session", "session_id", sessionID)
	return nil
}

// sqlcArtifactToArtifact converts sqlc.Artifact to artifact.Artifact.
func sqlcArtifactToArtifact(sa sqlc.Artifact) *Artifact {
	a := &Artifact{
		ID:             pgUUIDToUUID(sa.ID),
		SessionID:      pgUUIDToUUID(sa.SessionID),
		Filename:       sa.Filename,
		Type:           Type(sa.Type),
		Title:          sa.Title,
		Content:        sa.Content,
		Version:        int(sa.Version),
		SequenceNumber: int(sa.SequenceNumber),
		CreatedAt:      sa.CreatedAt.Time,
		UpdatedAt:      sa.UpdatedAt.Time,
	}

	if sa.MessageID.Valid {
		msgID := pgUUIDToUUID(sa.MessageID)
		a.MessageID = &msgID
	}

	if sa.Language != nil {
		a.Language = *sa.Language
	}

	return a
}

// pgUUIDToUUID converts pgtype.UUID to uuid.UUID.
func pgUUIDToUUID(pgUUID pgtype.UUID) uuid.UUID {
	if !pgUUID.Valid {
		return uuid.Nil
	}
	return pgUUID.Bytes
}
