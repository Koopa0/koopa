package notion

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/koopa0/blog-backend/internal/project"
)

// syncProject handles C1: fetch Notion page properties, upsert to projects table.
func (h *Handler) syncProject(ctx context.Context, pageID string) error {
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		return fmt.Errorf("fetching notion page: %w", err)
	}

	title := titleProperty(page.Properties["Name"])
	if title == "" {
		return fmt.Errorf("notion page %s has no title", pageID)
	}

	status := statusProperty(page.Properties["Status"])
	localStatus := mapNotionProjectStatus(status, page.Archived)

	description := richTextProperty(page.Properties["Review Notes"])
	area := selectProperty(page.Properties["Tag"])
	deadline := dateProperty(page.Properties["Target Deadline"])

	slug := Slugify(title)

	p, err := h.projects.UpsertByNotionPageID(ctx, project.UpsertByNotionParams{
		Slug:         slug,
		Title:        title,
		Description:  description,
		Status:       localStatus,
		Area:         area,
		Deadline:     deadline,
		NotionPageID: pageID,
	})
	if err != nil {
		return fmt.Errorf("upserting project: %w", err)
	}

	h.logger.Info("project synced from notion",
		"page_id", pageID,
		"project_id", p.ID,
		"title", title,
		"status", localStatus,
	)

	return nil
}

// syncTaskActivity handles C2: if task is Done with a project relation, update project last_activity_at.
func (h *Handler) syncTaskActivity(ctx context.Context, pageID string) error {
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		return fmt.Errorf("fetching notion task page: %w", err)
	}

	status := statusProperty(page.Properties["Status"])
	if status != "Done" {
		h.logger.Debug("task not done, skipping", "page_id", pageID, "status", status)
		return nil
	}

	projectPageID := relationProperty(page.Properties["Project"])
	if projectPageID == "" {
		h.logger.Debug("done task has no project relation, skipping", "page_id", pageID)
		return nil
	}

	if err := h.projects.UpdateLastActivity(ctx, projectPageID); err != nil {
		return fmt.Errorf("updating project last activity: %w", err)
	}

	h.logger.Info("project activity updated from task",
		"task_page_id", pageID,
		"project_page_id", projectPageID,
	)

	return nil
}

// syncBook handles C5: if book Status=="Read", submit bookmark-generate flow job.
func (h *Handler) syncBook(ctx context.Context, pageID string) error {
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		return fmt.Errorf("fetching notion book page: %w", err)
	}

	status := statusProperty(page.Properties["Status"])
	if status != "Read" {
		h.logger.Debug("book not read, skipping", "page_id", pageID, "status", status)
		return nil
	}

	title := titleProperty(page.Properties["Title"])
	author := richTextProperty(page.Properties["Author"])
	description := richTextProperty(page.Properties["Description"])
	rating := selectProperty(page.Properties["Rating"])

	if h.jobs == nil {
		h.logger.Warn("no job submitter configured, cannot submit bookmark-generate")
		return nil
	}

	input, err := json.Marshal(map[string]string{
		"source":         "notion-book",
		"notion_page_id": pageID,
		"title":          title,
		"author":         author,
		"description":    description,
		"rating":         rating,
	})
	if err != nil {
		return fmt.Errorf("marshaling bookmark input: %w", err)
	}

	if err := h.jobs.Submit(ctx, "bookmark-generate", input, nil); err != nil {
		return fmt.Errorf("submitting bookmark-generate: %w", err)
	}

	h.logger.Info("bookmark-generate submitted for book",
		"page_id", pageID,
		"title", title,
		"author", author,
		"rating", rating,
	)

	return nil
}
