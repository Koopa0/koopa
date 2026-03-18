package notion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/task"
)

// buildSourceID creates a dedup key for Notion activity events.
// Format: pageID:status:YYYY-MM-DD — same page+status+day deduplicates.
func buildSourceID(pageID, status string) string {
	return pageID + ":" + status + ":" + time.Now().Format("2006-01-02")
}

// syncProject handles C1: fetch Notion page properties, upsert to projects table.
func (h *Handler) syncProject(ctx context.Context, pageID string) error {
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		return fmt.Errorf("fetching notion page: %w", err)
	}

	if page.InTrash {
		h.logger.Debug("skipping trashed page", "page_id", pageID)
		return ErrSkipped
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

	idSuffix := pageID
	if len(idSuffix) > 8 {
		idSuffix = idSuffix[:8]
	}
	slug := Slugify(title) + "-" + idSuffix

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

	// Record activity event (best-effort)
	if h.events != nil {
		sourceID := buildSourceID(pageID, string(localStatus))
		metadata, _ := json.Marshal(map[string]string{
			"status": string(localStatus),
			"title":  title,
			"area":   area,
		}) // best-effort
		if _, evErr := h.events.CreateEvent(ctx, activity.RecordParams{
			SourceID:  &sourceID,
			Timestamp: time.Now(),
			EventType: "project_update",
			Source:    "notion",
			Project:   &p.Slug,
			Title:     &title,
			Metadata:  metadata,
		}); evErr != nil {
			h.logger.Error("recording project activity event", "page_id", pageID, "error", evErr)
		}
	}

	return nil
}

// syncTask handles C2: upsert task to local DB, record activity event, update project last_activity_at on Done.
func (h *Handler) syncTask(ctx context.Context, pageID string) error {
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		return fmt.Errorf("fetching notion task page: %w", err)
	}

	if page.InTrash {
		return ErrSkipped
	}

	status := statusProperty(page.Properties["Status"])
	title := titleProperty(page.Properties["Task Name"])
	if title == "" {
		title = titleProperty(page.Properties["Name"])
	}

	localStatus := mapNotionTaskStatus(status)
	due := dateProperty(page.Properties["Due"])

	// Resolve project via fallback chain: task Project → parent task Project
	var projectSlug *string
	var projectID *uuid.UUID
	projectPageID := relationProperty(page.Properties["Project"])

	// Fallback: if task has no direct Project, check Parent Task
	if projectPageID == "" {
		parentTaskID := relationProperty(page.Properties["Parent Task"])
		if parentTaskID != "" {
			parentPage, parentErr := h.client.Page(ctx, parentTaskID)
			if parentErr != nil {
				h.logger.Warn("resolving parent task project",
					"task_page_id", pageID,
					"parent_task_id", parentTaskID,
					"error", parentErr,
				)
			} else {
				projectPageID = relationProperty(parentPage.Properties["Project"])
			}
		}
	}

	// Resolve project page ID → slug (for activity events)
	if projectPageID != "" && h.projectSlugs != nil {
		slug, slugErr := h.projectSlugs.SlugByNotionPageID(ctx, projectPageID)
		if slugErr == nil {
			projectSlug = &slug
		}
	}

	// Resolve project page ID → UUID (for tasks table FK)
	if projectPageID != "" && h.projectIDs != nil {
		id, idErr := h.projectIDs.IDByNotionPageID(ctx, projectPageID)
		if idErr == nil {
			projectID = &id
		}
	}

	// Upsert task to local DB (completed_at is managed by the DB via CASE expression)
	t, err := h.tasks.UpsertByNotionPageID(ctx, task.UpsertByNotionParams{
		Title:        title,
		Status:       localStatus,
		Due:          due,
		ProjectID:    projectID,
		NotionPageID: pageID,
	})
	if err != nil {
		return fmt.Errorf("upserting task: %w", err)
	}

	h.logger.Info("task synced from notion",
		"page_id", pageID,
		"task_id", t.ID,
		"title", title,
		"status", localStatus,
	)

	// Record activity event for ALL status changes (best-effort)
	if h.events != nil {
		sourceID := buildSourceID(pageID, status)
		meta := map[string]string{
			"status": status,
			"title":  title,
		}
		if projectSlug != nil {
			meta["project"] = *projectSlug
		}
		metadata, _ := json.Marshal(meta) // best-effort
		if _, evErr := h.events.CreateEvent(ctx, activity.RecordParams{
			SourceID:  &sourceID,
			Timestamp: time.Now(),
			EventType: "task_status_change",
			Source:    "notion",
			Project:   projectSlug,
			Title:     &title,
			Metadata:  metadata,
		}); evErr != nil {
			h.logger.Error("recording task activity event", "page_id", pageID, "error", evErr)
		}
	}

	// Update project last_activity_at on Done
	if localStatus == task.StatusDone && projectPageID != "" {
		if err := h.projects.UpdateLastActivity(ctx, projectPageID); err != nil {
			return fmt.Errorf("updating project last activity: %w", err)
		}
	}

	return nil
}

// syncBook handles C5: record book progress and submit bookmark-generate on "Read".
func (h *Handler) syncBook(ctx context.Context, pageID string) error {
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		return fmt.Errorf("fetching notion book page: %w", err)
	}

	if page.InTrash {
		return ErrSkipped
	}

	status := statusProperty(page.Properties["Status"])
	title := titleProperty(page.Properties["Title"])
	author := richTextProperty(page.Properties["Author"])
	description := richTextProperty(page.Properties["Description"])
	rating := selectProperty(page.Properties["Rating"])

	// Record activity event for ALL book status changes (best-effort)
	if h.events != nil {
		sourceID := buildSourceID(pageID, status)
		metadata, _ := json.Marshal(map[string]string{
			"status": status,
			"title":  title,
			"author": author,
			"rating": rating,
		}) // best-effort
		if _, evErr := h.events.CreateEvent(ctx, activity.RecordParams{
			SourceID:  &sourceID,
			Timestamp: time.Now(),
			EventType: "book_progress",
			Source:    "notion",
			Title:     &title,
			Metadata:  metadata,
		}); evErr != nil {
			h.logger.Error("recording book activity event", "page_id", pageID, "error", evErr)
		}
	}

	// Only submit bookmark-generate on "Read" (existing behavior preserved)
	if status != "Read" {
		h.logger.Debug("book not read, skipping bookmark", "page_id", pageID, "status", status)
		return nil
	}

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

// syncGoal handles goal sync: fetch Notion page properties, upsert to goals table.
func (h *Handler) syncGoal(ctx context.Context, pageID string) error {
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		return fmt.Errorf("fetching notion goal page: %w", err)
	}

	if page.InTrash {
		return ErrSkipped
	}

	title := titleProperty(page.Properties["Name"])
	if title == "" {
		return fmt.Errorf("notion goal page %s has no title", pageID)
	}

	status := statusProperty(page.Properties["Status"])
	localStatus := mapNotionGoalStatus(status)

	description := richTextProperty(page.Properties["Description"])
	area := selectProperty(page.Properties["Area"])
	quarter := selectProperty(page.Properties["Quarter"])
	deadline := dateProperty(page.Properties["Deadline"])

	g, err := h.goals.UpsertByNotionPageID(ctx, goal.UpsertByNotionParams{
		Title:        title,
		Description:  description,
		Status:       localStatus,
		Area:         area,
		Quarter:      quarter,
		Deadline:     deadline,
		NotionPageID: pageID,
	})
	if err != nil {
		return fmt.Errorf("upserting goal: %w", err)
	}

	h.logger.Info("goal synced from notion",
		"page_id", pageID,
		"goal_id", g.ID,
		"title", title,
		"status", localStatus,
	)

	// Record activity event (best-effort)
	if h.events != nil {
		sourceID := buildSourceID(pageID, string(localStatus))
		metadata, _ := json.Marshal(map[string]string{
			"status": string(localStatus),
			"area":   area,
			"title":  title,
		}) // best-effort
		if _, evErr := h.events.CreateEvent(ctx, activity.RecordParams{
			SourceID:  &sourceID,
			Timestamp: time.Now(),
			EventType: "goal_update",
			Source:    "notion",
			Title:     &title,
			Metadata:  metadata,
		}); evErr != nil {
			h.logger.Error("recording goal activity event", "page_id", pageID, "error", evErr)
		}
	}

	return nil
}
