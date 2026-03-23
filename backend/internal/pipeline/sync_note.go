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

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/obsidian"
)

// syncKnowledgeNotes fetches and upserts each knowledge note.
func (h *Handler) syncKnowledgeNotes(ctx context.Context, files []string) {
	for _, path := range files {
		if err := h.syncKnowledgeNote(ctx, path); err != nil {
			h.logger.Error("syncing knowledge note", "path", path, "error", err)
			continue
		}
		h.logger.Info("synced knowledge note", "path", path)
	}
}

// syncKnowledgeNote fetches a single file from GitHub and upserts it as a knowledge note.
func (h *Handler) syncKnowledgeNote(ctx context.Context, path string) error {
	raw, err := h.fetcher.FileContent(ctx, path)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", path, err)
	}

	parsed, body, err := obsidian.ParseKnowledge(raw)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	// type is hard required — skip if missing
	if parsed.Type == "" {
		h.logger.Warn("knowledge note missing type, skipping", "path", path)
		return nil
	}

	// compute content hash (SHA-256 of body only)
	bodyHash := sha256Hex(body)

	// check if body changed — skip SplitCamelCase if hash matches
	var searchText string
	existingHash, err := h.notes.ContentHash(ctx, path)
	isNewNote := errors.Is(err, note.ErrNotFound)
	hashChanged := err != nil || existingHash == nil || *existingHash != bodyHash

	if hashChanged {
		searchText = obsidian.SplitCamelCase(body)
	}

	// build upsert params
	p := note.UpsertParams{
		FilePath:    path,
		ContentHash: &bodyHash,
	}

	// set optional fields from parsed frontmatter
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
		p.SearchText = &searchText
	}

	// === BEGIN TRANSACTION: upsert note + tag sync + link sync ===
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning note sync tx for %s: %w", path, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on committed tx is no-op

	txNotes := h.notes.WithTx(tx)
	txTags := h.tags.WithTx(tx)

	upserted, err := txNotes.UpsertNote(ctx, &p)
	if err != nil {
		return fmt.Errorf("upserting note %s: %w", path, err)
	}

	// tag normalization (resolution runs outside tx for best-effort alias creation)
	resolved := h.tags.ResolveTags(ctx, parsed.Tags)
	var tagIDs []uuid.UUID
	for _, r := range resolved {
		if r.TagID != nil {
			tagIDs = append(tagIDs, *r.TagID)
		}
	}
	// junction sync within tx
	if err := txTags.SyncNoteTags(ctx, upserted.ID, tagIDs); err != nil {
		return fmt.Errorf("syncing tags for %s: %w", path, err)
	}

	// wikilink edge sync within tx (only when content changed — includes clearing old links)
	if h.noteLinks != nil && hashChanged && p.ContentText != nil {
		txLinks := h.noteLinks.WithTx(tx)
		links := obsidian.ParseWikilinks(*p.ContentText)
		noteLinks := make([]note.Link, len(links))
		for i, l := range links {
			noteLinks[i] = note.Link{TargetPath: l.Path}
			if l.Display != "" {
				noteLinks[i].LinkText = &l.Display
			}
		}
		if linkErr := txLinks.SyncNoteLinks(ctx, upserted.ID, noteLinks); linkErr != nil {
			return fmt.Errorf("syncing note links for %s: %w", path, linkErr)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing note sync tx for %s: %w", path, err)
	}
	// === END TRANSACTION ===

	// Record activity event (best-effort, outside tx). Dedup handled by ON CONFLICT on sourceID=bodyHash.
	if h.noteEvents != nil {
		h.recordNoteEvent(ctx, path, bodyHash, parsed, tagIDs, isNewNote)
	}

	return nil
}

// archiveKnowledgeNotes archives removed knowledge notes.
func (h *Handler) archiveKnowledgeNotes(ctx context.Context, files []string) {
	for _, path := range files {
		if err := h.notes.ArchiveNote(ctx, path); err != nil {
			h.logger.Error("archiving knowledge note", "path", path, "error", err)
			continue
		}
		h.logger.Info("archived knowledge note", "path", path)
	}
}

// recordNoteEvent records an activity event for a knowledge note sync (best-effort).
func (h *Handler) recordNoteEvent(ctx context.Context, filePath, bodyHash string, parsed *obsidian.Knowledge, tagIDs []uuid.UUID, isNew bool) {
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
		h.logger.Error("marshaling note event metadata", "path", filePath, "error", err)
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

	eventID, err := h.noteEvents.CreateEvent(ctx, &p)
	if err != nil {
		h.logger.Error("recording note activity event", "path", filePath, "error", err)
		return
	}

	if len(tagIDs) > 0 {
		if err := h.noteEvents.SyncEventTags(ctx, eventID, tagIDs); err != nil {
			h.logger.Error("syncing note event tags", "path", filePath, "error", err)
		}
	}
}

// sha256Hex returns the hex-encoded SHA-256 hash of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
