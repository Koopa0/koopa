package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	urlpath "path"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/github"
	"github.com/koopa0/blog-backend/internal/obsidian"
)

// SyncAllFromGitHub lists 10-Public-Content/ on GitHub and syncs each file.
func (cs *ContentSync) SyncAllFromGitHub(ctx context.Context) {
	slugs, err := cs.fetcher.ListDirectory(ctx, "10-Public-Content")
	if err != nil {
		cs.logger.Error("sync: listing github directory", "error", err)
		return
	}

	var synced, failed int
	for _, slug := range slugs {
		path := "10-Public-Content/" + slug + ".md"
		if err := cs.syncFile(ctx, path); err != nil {
			if errors.Is(err, github.ErrNotFound) {
				cs.logger.Warn("sync: file not found (deleted?)", "path", path)
			} else {
				cs.logger.Error("sync: syncing file", "path", path, "error", err)
			}
			failed++
			continue
		}
		synced++
	}

	cs.logger.Info("sync: complete",
		"total", len(slugs),
		"synced", synced,
		"failed", failed,
	)

	if synced > 0 {
		cs.logger.Warn("sync drift detected: hourly sync fixed items that webhooks missed",
			"synced", synced,
			"failed", failed,
		)
	}
}

// syncFiles fetches and upserts each markdown file.
func (cs *ContentSync) syncFiles(ctx context.Context, files []string) {
	for _, path := range files {
		if err := cs.syncFile(ctx, path); err != nil {
			cs.logger.Error("syncing file", "path", path, "error", err)
			continue
		}
		cs.logger.Info("synced file", "path", path)
	}
}

// syncFile fetches a single file from GitHub and upserts it as content.
func (cs *ContentSync) syncFile(ctx context.Context, path string) error {
	raw, err := cs.fetcher.FileContent(ctx, path)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", path, err)
	}

	parsed, body, err := obsidian.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	slug := slugFromPath(path)

	// resolve topic IDs from parsed topic slugs
	topicIDs := cs.resolveTopics(ctx, parsed.TopicSlugs)

	// determine content type
	contentType := content.TypeNote // default
	if parsed.ContentType != "" {
		contentType = content.Type(parsed.ContentType)
	}

	sourceType := content.SourceObsidian

	// check if content already exists
	existing, err := cs.contentReader.ContentBySlug(ctx, slug)
	if err == nil && existing != nil {
		return cs.updateExistingContent(ctx, existing, slug, parsed, body, contentType, sourceType, path, topicIDs)
	}

	// create new content
	created, err := cs.contentWriter.CreateContent(ctx, &content.CreateParams{
		Slug:        slug,
		Title:       parsed.Title,
		Body:        body,
		Type:        contentType,
		Status:      content.StatusDraft,
		Tags:        parsed.Tags,
		TopicIDs:    topicIDs,
		SourceType:  &sourceType,
		Source:      &path,
		ReviewLevel: content.ReviewLight,
	})
	if err != nil {
		return fmt.Errorf("creating content %s: %w", slug, err)
	}

	// publish if the obsidian file is marked as published
	if parsed.Published {
		if _, err := cs.contentWriter.PublishContent(ctx, created.ID); err != nil {
			return fmt.Errorf("publishing content %s: %w", slug, err)
		}
	}

	cs.submitContentReview(ctx, created.ID)
	return nil
}

// updateExistingContent updates an already-synced content entry, optionally publishing it.
func (cs *ContentSync) updateExistingContent(ctx context.Context, existing *content.Content, slug string, parsed *obsidian.Parsed, body string, contentType content.Type, sourceType content.SourceType, path string, topicIDs []uuid.UUID) error {
	status := content.StatusDraft
	if parsed.Published {
		status = content.StatusPublished
	}
	_, updateErr := cs.contentWriter.UpdateContent(ctx, existing.ID, &content.UpdateParams{
		Title:      &parsed.Title,
		Body:       &body,
		Type:       &contentType,
		Status:     &status,
		Tags:       parsed.Tags,
		TopicIDs:   topicIDs,
		SourceType: &sourceType,
		Source:     &path,
	})
	if updateErr != nil {
		return fmt.Errorf("updating content %s: %w", slug, updateErr)
	}

	// publish if the obsidian file is marked as published and not yet published
	if parsed.Published && existing.Status != content.StatusPublished {
		if _, publishErr := cs.contentWriter.PublishContent(ctx, existing.ID); publishErr != nil {
			return fmt.Errorf("publishing content %s: %w", slug, publishErr)
		}
	}

	cs.submitContentReview(ctx, existing.ID)
	return nil
}

// submitContentReview submits a content-review flow job.
// Errors are logged but not propagated — content sync should not fail
// because the AI pipeline is unavailable.
func (cs *ContentSync) submitContentReview(ctx context.Context, contentID uuid.UUID) {
	if cs.jobs == nil {
		return
	}
	input, err := json.Marshal(map[string]string{"content_id": contentID.String()})
	if err != nil {
		cs.logger.Error("marshaling content-review input", "content_id", contentID, "error", err)
		return
	}
	if err := cs.jobs.Submit(ctx, "content-review", input, &contentID); err != nil {
		cs.logger.Error("submitting content-review", "content_id", contentID, "error", err)
	}
}

// resolveTopics looks up topic IDs for the given slugs, skipping unknown ones.
func (cs *ContentSync) resolveTopics(ctx context.Context, slugs []string) []uuid.UUID {
	var ids []uuid.UUID
	for _, slug := range slugs {
		id, err := cs.topics(ctx, slug)
		if err != nil {
			cs.logger.Debug("topic not found, skipping", "slug", slug)
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

// archiveRemovedFiles archives content for deleted markdown files.
func (cs *ContentSync) archiveRemovedFiles(ctx context.Context, files []string) {
	for _, path := range files {
		slug := slugFromPath(path)
		existing, err := cs.contentReader.ContentBySlug(ctx, slug)
		if err != nil {
			// not found — already deleted or never synced, skip
			cs.logger.Debug("removed file not found in db, skipping", "path", path, "slug", slug)
			continue
		}
		if err := cs.contentWriter.DeleteContent(ctx, existing.ID); err != nil {
			cs.logger.Error("archiving removed file", "path", path, "slug", slug, "error", err)
			continue
		}
		cs.logger.Info("archived removed file", "path", path, "slug", slug)
	}
}

// filterPublicMarkdown returns only .md files under 10-Public-Content/.
func filterPublicMarkdown(files []string) []string {
	var result []string
	for _, f := range files {
		if strings.HasPrefix(f, "10-Public-Content/") && strings.HasSuffix(f, ".md") {
			result = append(result, f)
		}
	}
	return result
}

// slugFromPath extracts a URL slug from a file path.
// Example: "10-Public-Content/my-post.md" → "my-post"
func slugFromPath(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, ".md")
}

// excludedKnowledgePrefixes lists directories that should NOT be synced as knowledge notes.
var excludedKnowledgePrefixes = []string{
	"10-Public-Content/", // handled by A1 pipeline
	"99-System/",         // templates and system files
	".claude/",           // Claude Code skills/commands
	".obsidian/",         // Obsidian config
}

// filterKnowledgeMarkdown returns .md files that are NOT in excluded directories
// and NOT root-level files (README.md, CLAUDE.md, etc.).
func filterKnowledgeMarkdown(files []string) []string {
	var result []string
	for _, f := range files {
		if !strings.HasSuffix(f, ".md") {
			continue
		}
		// Sanitize path to prevent traversal (e.g. "foo/../99-System/bar.md").
		clean := urlpath.Clean(f)
		// exclude root-level .md files (no directory prefix)
		if !strings.Contains(clean, "/") {
			continue
		}
		excluded := false
		for _, prefix := range excludedKnowledgePrefixes {
			if strings.HasPrefix(clean, prefix) {
				excluded = true
				break
			}
		}
		if !excluded {
			result = append(result, clean)
		}
	}
	return result
}
