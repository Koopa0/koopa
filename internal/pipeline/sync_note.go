package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/activity"
	"github.com/Koopa0/koopa0.dev/internal/note"
	"github.com/Koopa0/koopa0.dev/internal/obsidian"
	"github.com/Koopa0/koopa0.dev/internal/tag"
)

// syncKnowledgeNotes fetches and upserts each knowledge note.
func (cs *ContentSync) syncKnowledgeNotes(ctx context.Context, files []string) {
	for _, path := range files {
		if err := cs.syncKnowledgeNote(ctx, path); err != nil {
			cs.logger.Error("syncing knowledge note", "path", path, "error", err)
			continue
		}
		cs.logger.Info("synced knowledge note", "path", path)
	}
}

// syncKnowledgeNote fetches a single file from GitHub and upserts it as a knowledge note.
func (cs *ContentSync) syncKnowledgeNote(ctx context.Context, path string) error {
	raw, err := cs.fetcher.FileContent(ctx, path)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", path, err)
	}

	parsed, body, err := obsidian.ParseKnowledge(raw)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	// type is hard required — skip if missing
	if parsed.Type == "" {
		cs.logger.Warn("knowledge note missing type, skipping", "path", path)
		return nil
	}

	bodyHash := sha256Hex(body)

	existingHash, err := cs.notes.ContentHash(ctx, path)
	isNewNote := errors.Is(err, note.ErrNotFound)
	hashChanged := err != nil || existingHash == nil || *existingHash != bodyHash

	p := buildUpsertParams(path, bodyHash, body, hashChanged, parsed)

	tagIDs, err := cs.syncNoteInTx(ctx, path, &p, parsed.Tags, hashChanged)
	if err != nil {
		return err
	}

	// Record activity event (best-effort, outside tx). Dedup handled by ON CONFLICT on sourceID=bodyHash.
	if cs.noteEvents != nil {
		cs.recordNoteEvent(ctx, path, bodyHash, parsed, tagIDs, isNewNote)
	}

	return nil
}

// buildUpsertParams constructs the note upsert parameters from parsed frontmatter.
func buildUpsertParams(path, bodyHash, body string, hashChanged bool, parsed *obsidian.Knowledge) note.UpsertParams {
	p := note.UpsertParams{
		FilePath:    path,
		ContentHash: &bodyHash,
	}

	if parsed.Title != "" {
		p.Title = &parsed.Title
	}
	p.Type = &parsed.Type
	if parsed.Source != "" {
		p.Source = &parsed.Source
	}
	if parsed.Context != "" {
		p.Context = &parsed.Context
	}
	if parsed.Status != "" {
		p.Status = &parsed.Status
	}
	p.Tags = parsed.Tags
	if parsed.Difficulty != "" {
		p.Difficulty = &parsed.Difficulty
	}
	if parsed.LeetcodeID != 0 && parsed.LeetcodeID <= math.MaxInt32 {
		id := int32(parsed.LeetcodeID) // #nosec G115 -- bounds checked above
		p.LeetcodeID = &id
	}
	if parsed.Book != "" {
		p.Book = &parsed.Book
	}
	if parsed.Chapter != "" {
		p.Chapter = &parsed.Chapter
	}
	if parsed.NotionTaskID != "" {
		p.NotionTaskID = &parsed.NotionTaskID
	}

	if hashChanged {
		p.ContentText = &body
	}

	return p
}

// syncNoteInTx performs the transactional portion of note sync: upsert, tag sync, link sync.
func (cs *ContentSync) syncNoteInTx(ctx context.Context, path string, p *note.UpsertParams, rawTags []string, hashChanged bool) ([]uuid.UUID, error) {
	tx, err := cs.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning note sync tx for %s: %w", path, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on committed tx is no-op

	txNotes := note.NewStore(tx)
	txTags := tag.NewStore(tx)

	upserted, err := txNotes.UpsertNote(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("upserting note %s: %w", path, err)
	}

	tagIDs := cs.resolveTagIDs(ctx, rawTags)
	if err := txTags.SyncNoteTags(ctx, upserted.ID, tagIDs); err != nil {
		return nil, fmt.Errorf("syncing tags for %s: %w", path, err)
	}

	if err := cs.syncNoteLinks(ctx, tx, upserted.ID, path, p, hashChanged); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing note sync tx for %s: %w", path, err)
	}

	return tagIDs, nil
}

// resolveTagIDs resolves raw tag names to their UUIDs via the tag store.
func (cs *ContentSync) resolveTagIDs(ctx context.Context, rawTags []string) []uuid.UUID {
	resolved := cs.tags.ResolveTags(ctx, rawTags)
	var tagIDs []uuid.UUID
	for _, r := range resolved {
		if r.TagID != nil {
			tagIDs = append(tagIDs, *r.TagID)
		}
	}
	return tagIDs
}

// syncNoteLinks syncs wikilink edges within the transaction when content has changed.
func (cs *ContentSync) syncNoteLinks(ctx context.Context, tx pgx.Tx, noteID int64, path string, p *note.UpsertParams, hashChanged bool) error {
	if cs.noteLinks == nil || !hashChanged || p.ContentText == nil {
		return nil
	}
	txLinks := note.NewStore(tx)
	links := obsidian.ParseWikilinks(*p.ContentText)
	noteLinks := make([]note.Link, len(links))
	for i, l := range links {
		noteLinks[i] = note.Link{TargetPath: l.Path}
		if l.Display != "" {
			noteLinks[i].LinkText = &l.Display
		}
	}
	if err := txLinks.SyncNoteLinks(ctx, noteID, noteLinks); err != nil {
		return fmt.Errorf("syncing note links for %s: %w", path, err)
	}
	return nil
}

// archiveKnowledgeNotes archives removed knowledge notes.
func (cs *ContentSync) archiveKnowledgeNotes(ctx context.Context, files []string) {
	for _, path := range files {
		if err := cs.notes.ArchiveNote(ctx, path); err != nil {
			cs.logger.Error("archiving knowledge note", "path", path, "error", err)
			continue
		}
		cs.logger.Info("archived knowledge note", "path", path)
	}
}

// recordNoteEvent records an activity event for a knowledge note sync (best-effort).
func (cs *ContentSync) recordNoteEvent(ctx context.Context, filePath, bodyHash string, parsed *obsidian.Knowledge, tagIDs []uuid.UUID, isNew bool) {
	eventType := "note_updated"
	if isNew {
		eventType = "note_created"
	}

	// source_id: bodyHash for dedup — each content change creates one event,
	// re-syncs of unchanged content are deduplicated.
	sourceID := bodyHash

	// metadata via json.Marshal to avoid JSON injection from file paths
	meta, err := json.Marshal(map[string]string{
		"note_type": parsed.Type,
		"file_path": filePath,
	})
	if err != nil {
		cs.logger.Error("marshaling note event metadata", "path", filePath, "error", err)
		return
	}

	var titlePtr *string
	if parsed.Title != "" {
		titlePtr = &parsed.Title
	}

	var contextPtr *string
	if parsed.Context != "" {
		contextPtr = &parsed.Context
	}

	p := activity.RecordParams{
		SourceID:  &sourceID,
		Timestamp: time.Now(),
		EventType: eventType,
		Source:    "obsidian",
		Project:   contextPtr,
		Title:     titlePtr,
		Metadata:  meta,
	}

	eventID, err := cs.noteEvents.CreateEvent(ctx, &p)
	if err != nil {
		cs.logger.Error("recording note activity event", "path", filePath, "error", err)
		return
	}

	if len(tagIDs) > 0 {
		if err := cs.noteEvents.SyncEventTags(ctx, eventID, tagIDs); err != nil {
			cs.logger.Error("syncing note event tags", "path", filePath, "error", err)
		}
	}
}

// sha256Hex returns the hex-encoded SHA-256 hash of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
