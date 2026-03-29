package notion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/koopa0/blog-backend/internal/activity"
)

// Archiver archives and cleans up records by Notion page ID.
// Implemented by task.Store, project.Store, goal.Store.
type Archiver interface {
	ArchiveByNotionPageID(ctx context.Context, notionPageID string) (int64, error)
	ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error)
}

// ProjectResolver resolves project identifiers from Notion page IDs.
// Implemented by project.Store.
type ProjectResolver interface {
	SlugByNotionPageID(ctx context.Context, notionPageID string) (string, error)
	IDByNotionPageID(ctx context.Context, notionPageID string) (uuid.UUID, error)
	UpdateLastActivity(ctx context.Context, notionPageID string) error
}

// GoalResolver resolves goal IDs from Notion page IDs.
// Implemented by goal.Store.
type GoalResolver interface {
	IDByNotionPageID(ctx context.Context, notionPageID string) (uuid.UUID, error)
}

// buildSourceID creates a dedup key for Notion activity events.
// Format: pageID:status -- only status changes produce new events.
// The DB unique index (source, event_type, source_id) handles dedup.
func buildSourceID(pageID, status string) string {
	return pageID + ":" + status
}

// syncProject fetches a Notion page by ID and upserts it. Used by webhooks.
func (h *Handler) syncProject(ctx context.Context, pageID string) error {
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		return fmt.Errorf("fetching notion page: %w", err)
	}

	if page.InTrash || page.Archived {
		if _, archErr := h.projectArchiver.ArchiveByNotionPageID(ctx, pageID); archErr != nil {
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
	title := TitleProperty(props["Name"])
	if title == "" {
		return fmt.Errorf("notion page %s has no title", pageID)
	}

	status := StatusProperty(props["Status"])
	area := h.resolveRelationTitle(ctx, props["Tag"])

	// Resolve Goal relation -> local goal UUID
	var goalID *uuid.UUID
	goalPageID := RelationProperty(props["Goal"])
	if goalPageID != "" && h.goalResolver != nil {
		if id, err := h.goalResolver.IDByNotionPageID(ctx, goalPageID); err == nil {
			goalID = &id
		}
	}

	description := RichTextProperty(props["Review Notes"])
	deadline := DateProperty(props["Target Deadline"])

	if h.projectSync == nil {
		return fmt.Errorf("project sync not configured")
	}
	if err := h.projectSync(ctx, &ProjectSyncInput{
		PageID:      pageID,
		Title:       title,
		Status:      status,
		Description: description,
		Area:        area,
		GoalID:      goalID,
		Deadline:    deadline,
	}); err != nil {
		return err
	}

	h.logger.Info("project synced from notion",
		"page_id", pageID,
		"title", title,
		"status", status,
	)

	// Record activity event (best-effort)
	if h.events != nil {
		now := time.Now()
		sourceID := buildSourceID(pageID, status)
		metadata, _ := json.Marshal(map[string]string{
			"status": status,
			"title":  title,
			"area":   area,
		}) // best-effort
		if _, evErr := h.events.CreateEvent(ctx, &activity.RecordParams{
			SourceID:  &sourceID,
			Timestamp: now,
			EventType: "project_update",
			Source:    "notion",
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
		if _, archErr := h.taskArchiver.ArchiveByNotionPageID(ctx, pageID); archErr != nil {
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
	title := TitleProperty(props["Task Name"])
	if title == "" {
		title = TitleProperty(props["Name"])
	}
	status := StatusProperty(props["Status"])

	// Resolve project page ID (with parent-task fallback)
	projectPageID := RelationProperty(props["Project"])
	if projectPageID == "" {
		projectPageID = h.resolveParentProject(ctx, pageID, props)
	}

	var projectSlug *string
	if projectPageID != "" && h.projectResolver != nil {
		if slug, slugErr := h.projectResolver.SlugByNotionPageID(ctx, projectPageID); slugErr == nil {
			projectSlug = &slug
		}
	}

	// Extract remaining task properties
	due := DateProperty(props["Due"])
	energy := SelectProperty(props["Energy"])
	priority := StatusProperty(props["Priority"])
	recurInterval := NumberProperty(props["Recur Interval"])
	recurUnit := SelectProperty(props["Recur Unit"])
	myDay := CheckboxProperty(props["My Day"])
	description := RichTextProperty(props["Description"])

	if h.taskSync == nil {
		return fmt.Errorf("task sync not configured")
	}
	if err := h.taskSync(ctx, &TaskSyncInput{
		PageID:        pageID,
		Title:         title,
		Status:        status,
		Due:           due,
		Energy:        energy,
		Priority:      priority,
		RecurInterval: recurInterval,
		RecurUnit:     recurUnit,
		MyDay:         myDay,
		Description:   description,
		ProjectPageID: projectPageID,
	}); err != nil {
		return err
	}

	h.logger.Info("task synced from notion",
		"page_id", pageID,
		"title", title,
		"status", status,
	)

	// Record activity event for ALL status changes (best-effort)
	if h.events != nil {
		now := time.Now()
		sourceID := buildSourceID(pageID, status)
		meta := map[string]string{
			"status": status,
			"title":  title,
		}
		if projectSlug != nil {
			meta["project"] = *projectSlug
		}
		metadata, _ := json.Marshal(meta) // best-effort
		if _, evErr := h.events.CreateEvent(ctx, &activity.RecordParams{
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
	if status == "Done" && projectPageID != "" && h.projectResolver != nil {
		if err := h.projectResolver.UpdateLastActivity(ctx, projectPageID); err != nil {
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

	status := StatusProperty(page.Properties["Status"])
	title := TitleProperty(page.Properties["Title"])
	author := RichTextProperty(page.Properties["Author"])
	description := RichTextProperty(page.Properties["Description"])
	rating := SelectProperty(page.Properties["Rating"])

	// Record activity event for ALL book status changes (best-effort)
	if h.events != nil {
		now := time.Now()
		sourceID := buildSourceID(pageID, status)
		metadata, _ := json.Marshal(map[string]string{
			"status": status,
			"title":  title,
			"author": author,
			"rating": rating,
		}) // best-effort
		if _, evErr := h.events.CreateEvent(ctx, &activity.RecordParams{
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
		if _, archErr := h.goalArchiver.ArchiveByNotionPageID(ctx, pageID); archErr != nil {
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
// UB 3.0 Goals DB properties: Name (title), Status, Tag (relation->area), Target Deadline (date).
func (h *Handler) upsertGoal(ctx context.Context, pageID string, props map[string]json.RawMessage) error {
	title := TitleProperty(props["Name"])
	if title == "" {
		return fmt.Errorf("notion goal page %s has no title", pageID)
	}

	status := StatusProperty(props["Status"])

	// UB 3.0: Area is a Tag relation (not select)
	area := h.resolveRelationTitle(ctx, props["Tag"])

	deadline := DateProperty(props["Target Deadline"])

	if h.goalSync == nil {
		return fmt.Errorf("goal sync not configured")
	}
	if err := h.goalSync(ctx, &GoalSyncInput{
		PageID:   pageID,
		Title:    title,
		Status:   status,
		Area:     area,
		Deadline: deadline,
	}); err != nil {
		return err
	}

	h.logger.Info("goal synced from notion",
		"page_id", pageID,
		"title", title,
		"status", status,
	)

	// Record activity event (best-effort)
	if h.events != nil {
		now := time.Now()
		sourceID := buildSourceID(pageID, status)
		metadata, _ := json.Marshal(map[string]string{
			"status": status,
			"area":   area,
			"title":  title,
		}) // best-effort
		if _, evErr := h.events.CreateEvent(ctx, &activity.RecordParams{
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

// resolveRelationTitle extracts the first relation page ID from a property
// and fetches the page title via the Notion API. Returns "" on any failure
// (missing relation, API error, etc.) -- best-effort.
func (h *Handler) resolveRelationTitle(ctx context.Context, raw json.RawMessage) string {
	pageID := RelationProperty(raw)
	if pageID == "" {
		return ""
	}
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		h.logger.Warn("resolving relation page title", "page_id", pageID, "error", err)
		return ""
	}
	return TitleProperty(page.Properties["Name"])
}

// resolveParentProject looks up the parent task's Project relation.
func (h *Handler) resolveParentProject(ctx context.Context, pageID string, props map[string]json.RawMessage) string {
	parentTaskID := RelationProperty(props["Parent Task"])
	if parentTaskID == "" {
		return ""
	}
	parentPage, parentErr := h.client.Page(ctx, parentTaskID)
	if parentErr != nil {
		h.logger.Warn("resolving parent task project",
			"task_page_id", pageID,
			"parent_task_id", parentTaskID,
			"error", parentErr,
		)
		return ""
	}
	return RelationProperty(parentPage.Properties["Project"])
}
