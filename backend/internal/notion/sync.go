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
// Format: pageID:status — only status changes produce new events.
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
	area := h.resolveRelationTitle(ctx, props["Tag"])
	deadline := dateProperty(props["Target Deadline"])

	// Resolve Goal relation → local goal UUID
	var goalID *uuid.UUID
	goalPageID := relationProperty(props["Goal"])
	if goalPageID != "" && h.goalIDs != nil {
		if id, err := h.goalIDs.IDByNotionPageID(ctx, goalPageID); err == nil {
			goalID = &id
		}
	}

	idSuffix := pageID
	if len(idSuffix) > 8 {
		idSuffix = idSuffix[:8]
	}
	slug := Slugify(title) + "-" + idSuffix

	p, err := h.projects.UpsertByNotionPageID(ctx, &project.UpsertByNotionParams{
		Slug:         slug,
		Title:        title,
		Description:  description,
		Status:       localStatus,
		Area:         area,
		GoalID:       goalID,
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
		sourceID := buildSourceID(pageID, string(localStatus))
		metadata, _ := json.Marshal(map[string]string{
			"status": string(localStatus),
			"title":  title,
			"area":   area,
		}) // best-effort
		if _, evErr := h.events.CreateEvent(ctx, &activity.RecordParams{
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

// taskProps holds the extracted Notion properties for a task.
type taskProps struct {
	title         string
	status        string
	localStatus   task.Status
	due           *time.Time
	energy        string
	priority      string
	recurInterval *int32
	recurUnit     string
	myDay         bool
	description   string
	projectPageID string
}

// extractTaskProps reads and maps all relevant Notion properties for a task.
func extractTaskProps(props map[string]json.RawMessage) taskProps {
	title := titleProperty(props["Task Name"])
	if title == "" {
		title = titleProperty(props["Name"])
	}
	status := statusProperty(props["Status"])
	return taskProps{
		title:         title,
		status:        status,
		localStatus:   mapNotionTaskStatus(status),
		due:           dateProperty(props["Due"]),
		energy:        selectProperty(props["Energy"]),
		priority:      statusProperty(props["Priority"]),
		recurInterval: numberProperty(props["Recur Interval"]),
		recurUnit:     selectProperty(props["Recur Unit"]),
		myDay:         checkboxProperty(props["My Day"]),
		description:   richTextProperty(props["Description"]),
		projectPageID: relationProperty(props["Project"]),
	}
}

// resolveTaskProject resolves the project page ID (with parent-task fallback),
// then looks up the local slug and UUID.
func (h *Handler) resolveTaskProject(ctx context.Context, pageID, projectPageID string, props map[string]json.RawMessage) (resolvedPageID string, projectSlug *string, projectID *uuid.UUID) {
	resolvedPageID = projectPageID

	// Fallback: if task has no direct Project, check Parent Task.
	// This requires an extra API call per subtask — acceptable at personal-project scale.
	if resolvedPageID == "" {
		resolvedPageID = h.resolveParentProject(ctx, pageID, props)
	}

	if resolvedPageID == "" {
		return resolvedPageID, nil, nil
	}

	// Resolve project page ID → slug (for activity events) and UUID (for tasks table FK)
	if h.projectStore != nil {
		slug, slugErr := h.projectStore.SlugByNotionPageID(ctx, resolvedPageID)
		if slugErr == nil {
			projectSlug = &slug
		}
		id, idErr := h.projectStore.IDByNotionPageID(ctx, resolvedPageID)
		if idErr == nil {
			projectID = &id
		}
	}

	return resolvedPageID, projectSlug, projectID
}

// resolveParentProject looks up the parent task's Project relation.
func (h *Handler) resolveParentProject(ctx context.Context, pageID string, props map[string]json.RawMessage) string {
	parentTaskID := relationProperty(props["Parent Task"])
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
	return relationProperty(parentPage.Properties["Project"])
}

// upsertTask contains the shared task sync logic.
func (h *Handler) upsertTask(ctx context.Context, pageID string, props map[string]json.RawMessage) error {
	tp := extractTaskProps(props)
	projectPageID, projectSlug, projectID := h.resolveTaskProject(ctx, pageID, tp.projectPageID, props)

	t, err := h.tasks.UpsertByNotionPageID(ctx, &task.UpsertByNotionParams{
		Title:         tp.title,
		Status:        tp.localStatus,
		Due:           tp.due,
		ProjectID:     projectID,
		NotionPageID:  pageID,
		Energy:        tp.energy,
		Priority:      tp.priority,
		RecurInterval: tp.recurInterval,
		RecurUnit:     tp.recurUnit,
		MyDay:         tp.myDay,
		Description:   tp.description,
	})
	if err != nil {
		return fmt.Errorf("upserting task: %w", err)
	}

	h.logger.Info("task synced from notion",
		"page_id", pageID,
		"task_id", t.ID,
		"title", tp.title,
		"status", tp.localStatus,
	)

	// Record activity event for ALL status changes (best-effort)
	if h.events != nil {
		now := time.Now()
		sourceID := buildSourceID(pageID, tp.status)
		meta := map[string]string{
			"status": tp.status,
			"title":  tp.title,
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
			Title:     &tp.title,
			Metadata:  metadata,
		}); evErr != nil {
			h.logger.Error("recording task activity event", "page_id", pageID, "error", evErr)
		}
	}

	// Update project last_activity_at on Done
	if tp.localStatus == task.StatusDone && projectPageID != "" {
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
// UB 3.0 Goals DB properties: Name (title), Status, Tag (relation→area), Target Deadline (date).
func (h *Handler) upsertGoal(ctx context.Context, pageID string, props map[string]json.RawMessage) error {
	title := titleProperty(props["Name"])
	if title == "" {
		return fmt.Errorf("notion goal page %s has no title", pageID)
	}

	status := statusProperty(props["Status"])
	localStatus := mapNotionGoalStatus(status)

	// UB 3.0: Area is a Tag relation (not select), Deadline is "Target Deadline" (not "Deadline")
	area := h.resolveRelationTitle(ctx, props["Tag"])
	deadline := dateProperty(props["Target Deadline"])

	g, err := h.goals.UpsertByNotionPageID(ctx, &goal.UpsertByNotionParams{
		Title:        title,
		Status:       localStatus,
		Area:         area,
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
		sourceID := buildSourceID(pageID, string(localStatus))
		metadata, _ := json.Marshal(map[string]string{
			"status": string(localStatus),
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
// (missing relation, API error, etc.) — best-effort.
func (h *Handler) resolveRelationTitle(ctx context.Context, raw json.RawMessage) string {
	pageID := relationProperty(raw)
	if pageID == "" {
		return ""
	}
	page, err := h.client.Page(ctx, pageID)
	if err != nil {
		h.logger.Warn("resolving relation page title", "page_id", pageID, "error", err)
		return ""
	}
	return titleProperty(page.Properties["Name"])
}
