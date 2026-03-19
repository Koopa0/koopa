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
func buildSourceID(pageID, status string, now time.Time) string {
	return pageID + ":" + status + ":" + now.Format("2006-01-02")
}

// syncProject fetches a Notion page by ID and upserts it. Used by webhooks.
func (h *Handler) syncProject(ctx context.Context, pageID string) error {
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		return fmt.Errorf("fetching notion page: %w", err)
	}

	if page.InTrash || page.Archived {
		if _, archErr := h.projects.ArchiveByNotionPageID(ctx, pageID); archErr != nil {
			return fmt.Errorf("archiving trashed project %s: %w", pageID, archErr)
		}
		return ErrSkipped
	}

	return h.upsertProject(ctx, pageID, page.Properties)
}

// syncProjectFromResult upserts a project from a pre-fetched QueryDataSource result.
// Used by SyncAll to avoid per-page API calls.
func (h *Handler) syncProjectFromResult(ctx context.Context, result DatabaseQueryResult) error {
	return h.upsertProject(ctx, result.ID, result.Properties)
}

// upsertProject contains the shared project sync logic.
func (h *Handler) upsertProject(ctx context.Context, pageID string, props map[string]json.RawMessage) error {
	title := titleProperty(props["Name"])
	if title == "" {
		return fmt.Errorf("notion page %s has no title", pageID)
	}

	status := statusProperty(props["Status"])
	localStatus := mapNotionProjectStatus(status)

	description := richTextProperty(props["Review Notes"])
	area := selectProperty(props["Tag"])
	deadline := dateProperty(props["Target Deadline"])

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
		now := time.Now()
		sourceID := buildSourceID(pageID, string(localStatus), now)
		metadata, _ := json.Marshal(map[string]string{
			"status": string(localStatus),
			"title":  title,
			"area":   area,
		}) // best-effort
		if _, evErr := h.events.CreateEvent(ctx, activity.RecordParams{
			SourceID:  &sourceID,
			Timestamp: now,
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

// syncTask fetches a Notion page by ID and upserts it. Used by webhooks.
func (h *Handler) syncTask(ctx context.Context, pageID string) error {
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		return fmt.Errorf("fetching notion task page: %w", err)
	}

	if page.InTrash || page.Archived {
		if _, archErr := h.tasks.ArchiveByNotionPageID(ctx, pageID); archErr != nil {
			return fmt.Errorf("archiving trashed task %s: %w", pageID, archErr)
		}
		return ErrSkipped
	}

	return h.upsertTask(ctx, pageID, page.Properties)
}

// syncTaskFromResult upserts a task from a pre-fetched QueryDataSource result.
func (h *Handler) syncTaskFromResult(ctx context.Context, result DatabaseQueryResult) error {
	return h.upsertTask(ctx, result.ID, result.Properties)
}

// upsertTask contains the shared task sync logic.
func (h *Handler) upsertTask(ctx context.Context, pageID string, props map[string]json.RawMessage) error {
	status := statusProperty(props["Status"])
	title := titleProperty(props["Task Name"])
	if title == "" {
		title = titleProperty(props["Name"])
	}

	localStatus := mapNotionTaskStatus(status)
	due := dateProperty(props["Due"])

	// Resolve project via fallback chain: task Project → parent task Project
	var projectSlug *string
	var projectID *uuid.UUID
	projectPageID := relationProperty(props["Project"])

	// Fallback: if task has no direct Project, check Parent Task.
	// This requires an extra API call per subtask — acceptable at personal-project scale.
	if projectPageID == "" {
		parentTaskID := relationProperty(props["Parent Task"])
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
		now := time.Now()
		sourceID := buildSourceID(pageID, status, now)
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
			Timestamp: now,
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

// syncBook fetches a Notion page by ID and processes book progress. Used by webhooks.
func (h *Handler) syncBook(ctx context.Context, pageID string) error {
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		return fmt.Errorf("fetching notion book page: %w", err)
	}

	if page.InTrash || page.Archived {
		return ErrSkipped
	}

	status := statusProperty(page.Properties["Status"])
	title := titleProperty(page.Properties["Title"])
	author := richTextProperty(page.Properties["Author"])
	description := richTextProperty(page.Properties["Description"])
	rating := selectProperty(page.Properties["Rating"])

	// Record activity event for ALL book status changes (best-effort)
	if h.events != nil {
		now := time.Now()
		sourceID := buildSourceID(pageID, status, now)
		metadata, _ := json.Marshal(map[string]string{
			"status": status,
			"title":  title,
			"author": author,
			"rating": rating,
		}) // best-effort
		if _, evErr := h.events.CreateEvent(ctx, activity.RecordParams{
			SourceID:  &sourceID,
			Timestamp: now,
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

// syncGoal fetches a Notion page by ID and upserts it. Used by webhooks.
func (h *Handler) syncGoal(ctx context.Context, pageID string) error {
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		return fmt.Errorf("fetching notion goal page: %w", err)
	}

	if page.InTrash || page.Archived {
		if _, archErr := h.goals.ArchiveByNotionPageID(ctx, pageID); archErr != nil {
			return fmt.Errorf("archiving trashed goal %s: %w", pageID, archErr)
		}
		return ErrSkipped
	}

	return h.upsertGoal(ctx, pageID, page.Properties)
}

// syncGoalFromResult upserts a goal from a pre-fetched QueryDataSource result.
func (h *Handler) syncGoalFromResult(ctx context.Context, result DatabaseQueryResult) error {
	return h.upsertGoal(ctx, result.ID, result.Properties)
}

// upsertGoal contains the shared goal sync logic.
func (h *Handler) upsertGoal(ctx context.Context, pageID string, props map[string]json.RawMessage) error {
	title := titleProperty(props["Name"])
	if title == "" {
		return fmt.Errorf("notion goal page %s has no title", pageID)
	}

	status := statusProperty(props["Status"])
	localStatus := mapNotionGoalStatus(status)

	description := richTextProperty(props["Description"])
	area := selectProperty(props["Area"])
	quarter := selectProperty(props["Quarter"])
	deadline := dateProperty(props["Deadline"])

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
		now := time.Now()
		sourceID := buildSourceID(pageID, string(localStatus), now)
		metadata, _ := json.Marshal(map[string]string{
			"status": string(localStatus),
			"area":   area,
			"title":  title,
		}) // best-effort
		if _, evErr := h.events.CreateEvent(ctx, activity.RecordParams{
			SourceID:  &sourceID,
			Timestamp: now,
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
