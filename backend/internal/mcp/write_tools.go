package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/notion"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/session"
	"github.com/koopa0/blog-backend/internal/tag"
	"github.com/koopa0/blog-backend/internal/task"
)

// --- complete_task ---

// CompleteTaskInput is the input for the complete_task tool.
type CompleteTaskInput struct {
	TaskID    string `json:"task_id,omitempty" jsonschema_description:"Notion page ID or local task UUID (most precise)"`
	TaskTitle string `json:"task_title,omitempty" jsonschema_description:"fuzzy match against pending task titles"`
	Notes     string `json:"notes,omitempty" jsonschema_description:"completion notes (e.g. solution summary)"`
}

// CompleteTaskOutput is the output of the complete_task tool.
type CompleteTaskOutput struct {
	TaskID              string           `json:"task_id"`
	Title               string           `json:"title"`
	Project             string           `json:"project,omitempty"`
	CompletedAt         string           `json:"completed_at"`
	IsRecurring         bool             `json:"is_recurring"`
	NextRecurrence      *string          `json:"next_recurrence,omitempty"`
	Warning             string           `json:"warning,omitempty"`
	RemainingMyDayTasks []myDayRemaining `json:"remaining_my_day_tasks"`
}

// myDayRemaining is a minimal task summary for post-completion next-task suggestion.
type myDayRemaining struct {
	TaskID   string `json:"task_id"`
	Title    string `json:"title"`
	Project  string `json:"project,omitempty"`
	Priority string `json:"priority,omitempty"`
	Energy   string `json:"energy,omitempty"`
}

func (s *Server) completeTask(ctx context.Context, _ *mcp.CallToolRequest, input CompleteTaskInput) (*mcp.CallToolResult, CompleteTaskOutput, error) {
	if input.TaskID == "" && input.TaskTitle == "" {
		return nil, CompleteTaskOutput{}, fmt.Errorf("either task_id or task_title is required")
	}

	t, err := s.resolveTask(ctx, input.TaskID, input.TaskTitle)
	if err != nil {
		return nil, CompleteTaskOutput{}, err
	}

	// Check if already completed today (recurring task double-complete detection)
	var warning string
	if t.CompletedAt != nil && t.CompletedAt.In(s.loc).Format(time.DateOnly) == time.Now().In(s.loc).Format(time.DateOnly) {
		warning = fmt.Sprintf("This recurring task was already completed today (%s). Completing again will advance the due date further.",
			t.CompletedAt.Format("2006-01-02 15:04"))
	}

	// Update via Notion API if the task has a Notion page ID
	if t.NotionPageID != nil && s.notionTasks != nil {
		if notionErr := s.notionTasks.UpdatePageStatus(ctx, *t.NotionPageID, "Done"); notionErr != nil {
			return nil, CompleteTaskOutput{}, fmt.Errorf("updating notion task status: %w", notionErr)
		}
	}

	// Update local DB
	updated, err := s.taskWriter.UpdateStatus(ctx, t.ID, task.StatusDone)
	if err != nil {
		return nil, CompleteTaskOutput{}, fmt.Errorf("completing task: %w", err)
	}

	out := CompleteTaskOutput{
		TaskID:      updated.ID.String(),
		Title:       updated.Title,
		CompletedAt: time.Now().Format(time.RFC3339),
		IsRecurring: updated.IsRecurring(),
		Warning:     warning,
	}

	// Calculate next recurrence server-side (not from Notion — race with Automation)
	if nextDue := updated.NextDue(); nextDue != nil {
		nd := nextDue.Format(time.DateOnly)
		out.NextRecurrence = &nd
	}

	s.logger.Info("task completed via mcp",
		"task_id", updated.ID,
		"title", updated.Title,
		"is_recurring", updated.IsRecurring(),
	)

	// Record activity event for audit trail (enables recurring task tracking)
	if s.activityWriter != nil {
		evTitle := fmt.Sprintf("Completed: %s", updated.Title)
		sourceID := fmt.Sprintf("task-complete-%s-%s", updated.ID, time.Now().Format(time.DateOnly))
		//nolint:errcheck // best-effort: don't fail task completion on event recording error
		s.activityWriter.CreateEvent(ctx, &activity.RecordParams{
			SourceID:  &sourceID,
			Timestamp: time.Now(),
			Source:    "mcp",
			EventType: "task_completed",
			Title:     &evTitle,
		})
	}

	// Attach remaining My Day tasks for next-task suggestion
	out.RemainingMyDayTasks = s.fetchRemainingMyDay(ctx, updated.ID)

	return nil, out, nil
}

// --- create_task ---

// CreateTaskInput is the input for the create_task tool.
type CreateTaskInput struct {
	Title    string `json:"title" jsonschema_description:"task title (required)"`
	Project  string `json:"project,omitempty" jsonschema_description:"project name, slug, or alias"`
	Due      string `json:"due,omitempty" jsonschema_description:"due date in YYYY-MM-DD format"`
	Priority string `json:"priority,omitempty" jsonschema_description:"Low, Medium, or High"`
	Energy   string `json:"energy,omitempty" jsonschema_description:"Low or High"`
	MyDay    bool   `json:"my_day,omitempty" jsonschema_description:"add to My Day"`
	Notes    string `json:"notes,omitempty" jsonschema_description:"task description"`
}

// CreateTaskOutput is the output of the create_task tool.
type CreateTaskOutput struct {
	TaskID  string `json:"task_id"`
	Title   string `json:"title"`
	Due     string `json:"due,omitempty"`
	Project string `json:"project,omitempty"`
	Warning string `json:"warning,omitempty"`
}

func (s *Server) createTask(ctx context.Context, _ *mcp.CallToolRequest, input *CreateTaskInput) (*mcp.CallToolResult, CreateTaskOutput, error) {
	if input.Title == "" {
		return nil, CreateTaskOutput{}, fmt.Errorf("title is required")
	}
	if !validEnergy(input.Energy) {
		return nil, CreateTaskOutput{}, fmt.Errorf("invalid energy %q (must be High or Low)", input.Energy)
	}

	if s.notionTasks == nil {
		return nil, CreateTaskOutput{}, fmt.Errorf("notion task writer not configured")
	}

	taskDBID, err := s.resolveTaskDBID(ctx)
	if err != nil {
		return nil, CreateTaskOutput{}, err
	}

	// Resolve project before Notion create so we can pass the relation
	var projectID *uuid.UUID
	var projectTitle string
	var projectNotionPageID string
	if input.Project != "" {
		proj, projErr := s.resolveProject(ctx, input.Project)
		if projErr == nil {
			projectID = &proj.ID
			projectTitle = proj.Title
			if proj.NotionPageID != nil {
				projectNotionPageID = *proj.NotionPageID
			}
		}
	}

	// Parse due date for local DB
	var due *time.Time
	if input.Due != "" {
		d, parseErr := time.Parse(time.DateOnly, input.Due)
		if parseErr == nil {
			due = &d
		}
	}

	// Create in Notion with all properties
	pageID, err := s.notionTasks.CreateTask(ctx, &NotionCreateTaskParams{
		DatabaseID:  taskDBID,
		Title:       input.Title,
		DueDate:     input.Due,
		Description: input.Notes,
		Priority:    input.Priority,
		Energy:      input.Energy,
		MyDay:       input.MyDay,
		ProjectID:   projectNotionPageID,
	})
	if err != nil {
		return nil, CreateTaskOutput{}, fmt.Errorf("creating notion task: %w", err)
	}

	// Upsert to local DB immediately (don't wait for webhook)
	upsertParams := &task.UpsertByNotionParams{
		Title:        input.Title,
		Status:       task.StatusTodo,
		Due:          due,
		ProjectID:    projectID,
		NotionPageID: pageID,
		Energy:       input.Energy,
		Priority:     input.Priority,
		MyDay:        input.MyDay,
		Description:  input.Notes,
	}
	localTask, upsertErr := s.taskWriter.UpsertByNotionPageID(ctx, upsertParams)

	out := CreateTaskOutput{
		TaskID: pageID,
		Title:  input.Title,
		Due:    input.Due,
	}
	if projectTitle != "" {
		out.Project = projectTitle
	} else if input.Project != "" {
		out.Warning = fmt.Sprintf("task created but project %q not found", input.Project)
	}
	if localTask != nil {
		out.TaskID = localTask.ID.String()
	}
	if upsertErr != nil {
		s.logger.Error("create_task: local upsert failed (webhook will retry)", "error", upsertErr)
	}

	s.logger.Info("task created via mcp",
		"notion_page_id", pageID,
		"title", input.Title,
		"due", input.Due,
		"project", out.Project,
	)

	return nil, out, nil
}

// --- update_task ---

// UpdateTaskInput is the input for the update_task tool.
type UpdateTaskInput struct {
	TaskID    string  `json:"task_id,omitempty" jsonschema_description:"task UUID (most precise)"`
	TaskTitle string  `json:"task_title,omitempty" jsonschema_description:"fuzzy match against pending task titles"`
	NewTitle  *string `json:"new_title,omitempty" jsonschema_description:"rename the task to this value"`
	Status    *string `json:"status,omitempty" jsonschema_description:"To Do, Doing, or Done"`
	Due       *string `json:"due,omitempty" jsonschema_description:"ISO date (YYYY-MM-DD)"`
	Priority  *string `json:"priority,omitempty" jsonschema_description:"Low, Medium, or High"`
	Energy    *string `json:"energy,omitempty" jsonschema_description:"Low or High"`
	MyDay     *bool   `json:"my_day,omitempty" jsonschema_description:"set or clear My Day"`
	Project   *string `json:"project,omitempty" jsonschema_description:"project slug/alias/title"`
	Notes     *string `json:"notes,omitempty" jsonschema_description:"append to description"`
}

// UpdateTaskOutput is the output of the update_task tool.
type UpdateTaskOutput struct {
	TaskID  string `json:"task_id"`
	Title   string `json:"title"`
	Status  string `json:"status"`
	Due     string `json:"due,omitempty"`
	Updated string `json:"updated_at"`
}

func (s *Server) updateTask(ctx context.Context, _ *mcp.CallToolRequest, input *UpdateTaskInput) (*mcp.CallToolResult, UpdateTaskOutput, error) {
	if input.TaskID == "" && input.TaskTitle == "" {
		return nil, UpdateTaskOutput{}, fmt.Errorf("either task_id or task_title is required")
	}
	if input.Energy != nil && !validEnergy(*input.Energy) {
		return nil, UpdateTaskOutput{}, fmt.Errorf("invalid energy %q (must be High or Low)", *input.Energy)
	}

	t, err := s.resolveTask(ctx, input.TaskID, input.TaskTitle)
	if err != nil {
		return nil, UpdateTaskOutput{}, err
	}

	params := &task.UpdateParams{ID: t.ID}

	if input.NewTitle != nil {
		params.Title = input.NewTitle
	}
	if input.Status != nil {
		st := mapInputTaskStatus(*input.Status)
		params.Status = &st
	}
	if input.Due != nil {
		due, parseErr := time.Parse(time.DateOnly, *input.Due)
		if parseErr != nil {
			return nil, UpdateTaskOutput{}, fmt.Errorf("invalid due date %q (expected YYYY-MM-DD)", *input.Due)
		}
		params.Due = &due
	}
	if input.Priority != nil {
		params.Priority = input.Priority
	}
	if input.Energy != nil {
		params.Energy = input.Energy
	}
	if input.MyDay != nil {
		params.MyDay = input.MyDay
	}
	if input.Notes != nil {
		params.Description = input.Notes
	}
	var resolvedProject *project.Project
	if input.Project != nil {
		proj, projErr := s.resolveProject(ctx, *input.Project)
		if projErr == nil {
			resolvedProject = proj
			params.ProjectID = &proj.ID
		}
	}

	// Sync changed properties to Notion (best-effort, before local update)
	s.syncTaskToNotion(ctx, t, input, resolvedProject)

	updated, err := s.taskWriter.Update(ctx, params)
	if err != nil {
		return nil, UpdateTaskOutput{}, fmt.Errorf("updating task: %w", err)
	}

	out := UpdateTaskOutput{
		TaskID:  updated.ID.String(),
		Title:   updated.Title,
		Status:  string(updated.Status),
		Updated: updated.UpdatedAt.Format(time.RFC3339),
	}
	if updated.Due != nil {
		out.Due = updated.Due.Format(time.DateOnly)
	}

	return nil, out, nil
}

// syncTaskToNotion syncs changed task properties to Notion.
// It is best-effort: errors are logged but not returned.
func (s *Server) syncTaskToNotion(ctx context.Context, t *task.Task, input *UpdateTaskInput, resolvedProject *project.Project) {
	if t.NotionPageID == nil || s.notionTasks == nil {
		return
	}
	notionProps := buildNotionTaskProps(input)
	if resolvedProject != nil && resolvedProject.NotionPageID != nil {
		notionProps["Project"] = map[string]any{
			"relation": []map[string]string{{"id": *resolvedProject.NotionPageID}},
		}
	}
	if len(notionProps) == 0 {
		return
	}
	if notionErr := s.notionTasks.UpdatePageProperties(ctx, *t.NotionPageID, notionProps); notionErr != nil {
		s.logger.Warn("update_task: notion write-back failed", "task_id", t.ID, "error", notionErr)
	}
}

// --- batch_my_day ---

// BatchMyDayInput is the input for the batch_my_day tool.
type BatchMyDayInput struct {
	TaskIDs []string `json:"task_ids" jsonschema_description:"task UUIDs to set as My Day"`
	Clear   bool     `json:"clear,omitempty" jsonschema_description:"clear all existing My Day first"`
}

// BatchMyDayOutput is the output of the batch_my_day tool.
type BatchMyDayOutput struct {
	Cleared int `json:"cleared,omitempty"`
	Set     int `json:"set"`
}

func (s *Server) batchMyDay(ctx context.Context, _ *mcp.CallToolRequest, input BatchMyDayInput) (*mcp.CallToolResult, BatchMyDayOutput, error) {
	if len(input.TaskIDs) == 0 && !input.Clear {
		return nil, BatchMyDayOutput{}, fmt.Errorf("task_ids is required (or set clear: true)")
	}

	var out BatchMyDayOutput

	if input.Clear {
		// Sync to Notion before clearing local DB (best-effort)
		if s.notionTasks != nil {
			currentMyDay, myDayErr := s.tasks.MyDayTasksWithNotionPageID(ctx)
			if myDayErr != nil {
				s.logger.Warn("batch_my_day: fetching notion page ids for clear", "error", myDayErr)
			}
			for _, t := range currentMyDay {
				s.syncMyDayToNotion(ctx, t.NotionPageID, false)
			}
		}

		n, err := s.taskWriter.ClearAllMyDay(ctx)
		if err != nil {
			return nil, BatchMyDayOutput{}, fmt.Errorf("clearing my day: %w", err)
		}
		out.Cleared = int(n)
	}

	for _, idStr := range input.TaskIDs {
		id, parseErr := uuid.Parse(idStr)
		if parseErr != nil {
			return nil, BatchMyDayOutput{}, fmt.Errorf("invalid task_id %q: %w", idStr, parseErr)
		}
		if err := s.taskWriter.UpdateMyDay(ctx, id, true); err != nil {
			s.logger.Error("batch_my_day: setting my day", "task_id", idStr, "error", err)
			continue
		}
		out.Set++

		// Sync to Notion (best-effort)
		if s.notionTasks != nil {
			t, taskErr := s.tasks.TaskByID(ctx, id)
			if taskErr == nil && t.NotionPageID != nil {
				s.syncMyDayToNotion(ctx, *t.NotionPageID, true)
			}
		}
	}

	return nil, out, nil
}

// syncMyDayToNotion updates the My Day checkbox for a task in Notion.
// It is best-effort: errors are logged but not returned.
func (s *Server) syncMyDayToNotion(ctx context.Context, notionPageID string, value bool) {
	if s.notionTasks == nil || notionPageID == "" {
		return
	}
	props := map[string]any{"My Day": map[string]any{"checkbox": value}}
	if err := s.notionTasks.UpdatePageProperties(ctx, notionPageID, props); err != nil {
		s.logger.Warn("batch_my_day: notion sync failed", "notion_page_id", notionPageID, "error", err)
	}
}

// --- log_learning_session ---

// LogLearningSessionInput is the input for the log_learning_session tool.
type LogLearningSessionInput struct {
	Topic      string   `json:"topic" jsonschema:"required" jsonschema_description:"what was learned"`
	Source     string   `json:"source" jsonschema:"required" jsonschema_description:"leetcode, hackerrank, oreilly, ardanlabs, article, discussion"`
	Title      string   `json:"title" jsonschema:"required" jsonschema_description:"short title"`
	Body       string   `json:"body" jsonschema:"required" jsonschema_description:"markdown content: approach, concepts, insights"`
	Tags       []string `json:"tags,omitempty" jsonschema_description:"tags for categorization"`
	Project    string   `json:"project" jsonschema:"required" jsonschema_description:"project name, slug, or alias (use 'none' for unaffiliated learning)"`
	Difficulty string   `json:"difficulty,omitempty" jsonschema_description:"easy, medium, or hard"`
	ProblemURL string   `json:"problem_url,omitempty" jsonschema_description:"problem link"`
}

// LogLearningSessionOutput is the output of the log_learning_session tool.
type LogLearningSessionOutput struct {
	ContentID         string             `json:"content_id"`
	Slug              string             `json:"slug"`
	Title             string             `json:"title"`
	Status            string             `json:"status"`
	AutoCompletedTask *AutoCompletedTask `json:"auto_completed_task"`
}

// AutoCompletedTask reports the result of auto-completing a recurring task.
type AutoCompletedTask struct {
	TaskID  string  `json:"task_id"`
	Title   string  `json:"title"`
	NextDue *string `json:"next_due,omitempty"`
}

func (s *Server) logLearningSession(ctx context.Context, _ *mcp.CallToolRequest, input *LogLearningSessionInput) (*mcp.CallToolResult, LogLearningSessionOutput, error) {
	tags, err := validateLearningInput(input)
	if err != nil {
		return nil, LogLearningSessionOutput{}, err
	}
	if tags == nil {
		tags = []string{}
	}

	now := time.Now()
	topicSlug := tag.Slugify(input.Topic)
	slug := fmt.Sprintf("%s-til-%s", topicSlug, now.Format("2006-01-02"))
	source := fmt.Sprintf("claude:%s", input.Source)
	sourceType := content.SourceAIGenerated

	// Add metadata to body if provided
	body := input.Body
	if input.ProblemURL != "" {
		body = fmt.Sprintf("**Problem**: %s\n\n%s", input.ProblemURL, body)
	}
	if input.Difficulty != "" {
		body = fmt.Sprintf("**Difficulty**: %s\n\n%s", input.Difficulty, body)
	}

	params := &content.CreateParams{
		Slug:        slug,
		Title:       input.Title,
		Body:        body,
		Type:        content.TypeTIL,
		Status:      content.StatusPublished,
		Tags:        tags,
		Source:      &source,
		SourceType:  &sourceType,
		ReviewLevel: content.ReviewAuto,
	}
	created, err := s.createContentWithRetry(ctx, params, fmt.Sprintf("%s-til-%s", topicSlug, now.Format("2006-01-02")), now)
	if err != nil {
		return nil, LogLearningSessionOutput{}, fmt.Errorf("creating learning session: %w", err)
	}

	s.logger.Info("learning session logged",
		"content_id", created.ID,
		"topic", input.Topic,
		"source", input.Source,
	)

	out := LogLearningSessionOutput{
		ContentID: created.ID.String(),
		Slug:      created.Slug,
		Title:     created.Title,
		Status:    string(created.Status),
	}

	// Auto-complete matching recurring task (best-effort)
	if input.Project != "none" {
		out.AutoCompletedTask = s.autoCompleteRecurringTask(ctx, input.Project)
	}

	return nil, out, nil
}

// autoCompleteRecurringTask finds and completes a recurring task matching the
// project. Returns nil on any failure — auto-complete is best-effort and must
// never fail the primary log_learning_session operation.
func (s *Server) autoCompleteRecurringTask(ctx context.Context, projectInput string) *AutoCompletedTask {
	proj, err := s.resolveProject(ctx, projectInput)
	if err != nil {
		s.logger.Warn("auto-complete: project not found", "project", projectInput, "error", err)
		return nil
	}

	now := time.Now().In(s.loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, s.loc)
	// Pass end-of-day so due <= @today catches tasks due today (due stored as midnight)
	endOfDay := today.AddDate(0, 0, 1)

	t, err := s.tasks.RecurringTaskByProject(ctx, proj.ID, endOfDay)
	if err != nil {
		s.logger.Warn("auto-complete: query failed", "project", projectInput, "error", err)
		return nil
	}
	if t == nil {
		s.logger.Debug("auto-complete: no matching recurring task", "project", projectInput)
		return nil
	}

	// Check if already completed today (reuse same logic as completeTask)
	if t.CompletedAt != nil && t.CompletedAt.In(s.loc).Format(time.DateOnly) == now.Format(time.DateOnly) {
		s.logger.Info("auto-complete: task already completed today", "task_id", t.ID, "title", t.Title)
		return nil
	}

	// Complete the task via the existing completeTask flow
	_, completeOut, completeErr := s.completeTask(ctx, nil, CompleteTaskInput{
		TaskID: t.ID.String(),
	})
	if completeErr != nil {
		s.logger.Warn("auto-complete: complete failed", "task_id", t.ID, "error", completeErr)
		return nil
	}

	s.logger.Info("auto-complete: recurring task completed",
		"task_id", t.ID,
		"title", t.Title,
		"next_recurrence", completeOut.NextRecurrence,
	)

	return &AutoCompletedTask{
		TaskID:  completeOut.TaskID,
		Title:   completeOut.Title,
		NextDue: completeOut.NextRecurrence,
	}
}

// --- save_session_note ---

// SaveSessionNoteInput is the input for the save_session_note tool.
// Metadata uses map[string]any so the MCP JSON Schema renders as an object
// (json.RawMessage would serialize as array[integer] — a bare byte slice).
type SaveSessionNoteInput struct {
	NoteType string         `json:"note_type" jsonschema_description:"plan, reflection, context, metrics, or insight (required)"`
	Content  string         `json:"content" jsonschema_description:"note content text (required)"`
	Source   string         `json:"source" jsonschema_description:"claude, claude-code, or manual (required)"`
	Date     string         `json:"date,omitempty" jsonschema_description:"ISO date YYYY-MM-DD (default today)"`
	Metadata map[string]any `json:"metadata,omitempty" jsonschema_description:"optional JSON metadata object (e.g. {tasks_planned: 3, tasks_completed: 1, completion_rate: 33})"`
}

// SaveSessionNoteOutput is the output of the save_session_note tool.
type SaveSessionNoteOutput struct {
	ID        int64  `json:"id"`
	NoteDate  string `json:"note_date"`
	NoteType  string `json:"note_type"`
	CreatedAt string `json:"created_at"`
}

// validateSessionNoteInput checks required fields and enum values for SaveSessionNoteInput.
func validateSessionNoteInput(input SaveSessionNoteInput) error {
	if input.NoteType == "" {
		return fmt.Errorf("note_type is required")
	}
	if input.Content == "" {
		return fmt.Errorf("content is required")
	}
	if input.Source == "" {
		return fmt.Errorf("source is required")
	}

	switch input.NoteType {
	case "plan", "reflection", "context", "metrics", "insight":
		// valid
	default:
		return fmt.Errorf("invalid note_type %q (must be plan, reflection, context, metrics, or insight)", input.NoteType)
	}

	switch input.Source {
	case "claude", "claude-code", "manual":
		// valid
	default:
		return fmt.Errorf("invalid source %q (must be claude, claude-code, or manual)", input.Source)
	}

	return nil
}

func (s *Server) saveSessionNote(ctx context.Context, _ *mcp.CallToolRequest, input SaveSessionNoteInput) (*mcp.CallToolResult, SaveSessionNoteOutput, error) {
	if s.sessionWriter == nil {
		return nil, SaveSessionNoteOutput{}, fmt.Errorf("session notes not configured")
	}
	if err := validateSessionNoteInput(input); err != nil {
		return nil, SaveSessionNoteOutput{}, err
	}

	noteDate := time.Now()
	if input.Date != "" {
		parsed, err := time.Parse(time.DateOnly, input.Date)
		if err != nil {
			return nil, SaveSessionNoteOutput{}, fmt.Errorf("invalid date %q (expected YYYY-MM-DD)", input.Date)
		}
		noteDate = parsed
	}

	var metadataJSON json.RawMessage
	if len(input.Metadata) > 0 {
		var marshalErr error
		metadataJSON, marshalErr = json.Marshal(input.Metadata)
		if marshalErr != nil {
			return nil, SaveSessionNoteOutput{}, fmt.Errorf("marshaling metadata: %w", marshalErr)
		}
	}

	// Soft validation for insight notes: warn if missing key fields
	if input.NoteType == "insight" && len(input.Metadata) > 0 {
		if _, ok := input.Metadata["hypothesis"]; !ok {
			s.logger.Warn("insight saved without hypothesis")
		}
		if _, ok := input.Metadata["invalidation_condition"]; !ok {
			s.logger.Warn("insight saved without invalidation_condition")
		}
	}

	created, err := s.sessionWriter.CreateNote(ctx, &session.CreateParams{
		NoteDate: noteDate,
		NoteType: input.NoteType,
		Source:   input.Source,
		Content:  input.Content,
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, SaveSessionNoteOutput{}, fmt.Errorf("saving session note: %w", err)
	}

	s.logger.Info("session note saved",
		"id", created.ID,
		"type", created.NoteType,
		"source", created.Source,
		"date", created.NoteDate.Format(time.DateOnly),
	)

	return nil, SaveSessionNoteOutput{
		ID:        created.ID,
		NoteDate:  created.NoteDate.Format(time.DateOnly),
		NoteType:  created.NoteType,
		CreatedAt: created.CreatedAt.Format(time.RFC3339),
	}, nil
}

// --- helpers ---

// resolveTask finds a task by ID or title, returning an error if ambiguous.
func (s *Server) resolveTask(ctx context.Context, taskID, taskTitle string) (*task.Task, error) {
	if taskID != "" {
		id, parseErr := uuid.Parse(taskID)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid task_id %q", taskID)
		}
		t, err := s.tasks.TaskByID(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("task %q not found", taskID)
		}
		return t, nil
	}

	matches, err := s.tasks.PendingTasksByTitle(ctx, taskTitle)
	if err != nil {
		return nil, fmt.Errorf("searching tasks: %w", err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no pending task found matching %q", taskTitle)
	}
	if len(matches) > 1 {
		titles := make([]string, len(matches))
		for i := range matches {
			m := matches[i]
			titles[i] = fmt.Sprintf("- %s (id: %s)", m.Title, m.ID)
		}
		return nil, fmt.Errorf("ambiguous: %d tasks match %q, please specify task_id:\n%s",
			len(matches), taskTitle, joinLines(titles))
	}
	return &matches[0], nil
}

// --- update_project_status ---

// UpdateProjectStatusInput is the input for the update_project_status tool.
type UpdateProjectStatusInput struct {
	Project         string  `json:"project" jsonschema_description:"project name, slug, or alias (required)"`
	Status          string  `json:"status" jsonschema_description:"Planned, Doing, Ongoing, On Hold, or Done (required)"`
	ReviewNotes     *string `json:"review_notes,omitempty" jsonschema_description:"optional review notes to update description"`
	ExpectedCadence *string `json:"expected_cadence,omitempty" jsonschema_description:"project activity cadence: daily, weekly, biweekly, monthly, or on_hold"`
}

// UpdateProjectStatusOutput is the output of the update_project_status tool.
type UpdateProjectStatusOutput struct {
	Slug   string `json:"slug"`
	Title  string `json:"title"`
	Status string `json:"status"`
}

func (s *Server) updateProjectStatus(ctx context.Context, _ *mcp.CallToolRequest, input UpdateProjectStatusInput) (*mcp.CallToolResult, UpdateProjectStatusOutput, error) {
	if input.Project == "" {
		return nil, UpdateProjectStatusOutput{}, fmt.Errorf("project is required")
	}
	if input.Status == "" {
		return nil, UpdateProjectStatusOutput{}, fmt.Errorf("status is required")
	}

	if s.projectWriter == nil {
		return nil, UpdateProjectStatusOutput{}, fmt.Errorf("project writer not configured")
	}

	proj, err := s.resolveProject(ctx, input.Project)
	if err != nil {
		return nil, UpdateProjectStatusOutput{}, err
	}

	status := mapInputProjectStatus(input.Status)
	updated, err := s.projectWriter.UpdateStatus(ctx, proj.ID, status, input.ReviewNotes, input.ExpectedCadence)
	if err != nil {
		return nil, UpdateProjectStatusOutput{}, fmt.Errorf("updating project status: %w", err)
	}

	// Sync to Notion (best-effort)
	if proj.NotionPageID != nil && s.notionTasks != nil {
		notionProps := map[string]any{
			"Status": map[string]any{"status": map[string]string{"name": notion.LocalProjectStatusToNotion(status)}},
		}
		if input.ReviewNotes != nil && *input.ReviewNotes != "" {
			notionProps["Review Notes"] = map[string]any{
				"rich_text": []map[string]any{
					{"type": "text", "text": map[string]string{"content": *input.ReviewNotes}},
				},
			}
		}
		if notionErr := s.notionTasks.UpdatePageProperties(ctx, *proj.NotionPageID, notionProps); notionErr != nil {
			s.logger.Warn("update_project_status: notion write-back failed", "project", proj.Slug, "error", notionErr)
		}
	}

	return nil, UpdateProjectStatusOutput{
		Slug:   updated.Slug,
		Title:  updated.Title,
		Status: string(updated.Status),
	}, nil
}

// --- update_goal_status ---

// UpdateGoalStatusInput is the input for the update_goal_status tool.
type UpdateGoalStatusInput struct {
	GoalTitle string `json:"goal_title" jsonschema_description:"goal title (case-insensitive match, required)"`
	Status    string `json:"status" jsonschema_description:"Dream, Active, Achieved, or Abandoned (required)"`
}

// UpdateGoalStatusOutput is the output of the update_goal_status tool.
type UpdateGoalStatusOutput struct {
	Title  string `json:"title"`
	Status string `json:"status"`
	Area   string `json:"area,omitempty"`
}

func (s *Server) updateGoalStatus(ctx context.Context, _ *mcp.CallToolRequest, input UpdateGoalStatusInput) (*mcp.CallToolResult, UpdateGoalStatusOutput, error) {
	if input.GoalTitle == "" {
		return nil, UpdateGoalStatusOutput{}, fmt.Errorf("goal_title is required")
	}
	if input.Status == "" {
		return nil, UpdateGoalStatusOutput{}, fmt.Errorf("status is required")
	}

	if s.goalWriter == nil {
		return nil, UpdateGoalStatusOutput{}, fmt.Errorf("goal writer not configured")
	}

	g, err := s.goals.GoalByTitle(ctx, input.GoalTitle)
	if err != nil {
		return nil, UpdateGoalStatusOutput{}, fmt.Errorf("goal %q not found", input.GoalTitle)
	}

	status := mapInputGoalStatus(input.Status)
	updated, err := s.goalWriter.UpdateStatus(ctx, g.ID, status)
	if err != nil {
		return nil, UpdateGoalStatusOutput{}, fmt.Errorf("updating goal status: %w", err)
	}

	// Sync to Notion (best-effort)
	if g.NotionPageID != nil && s.notionTasks != nil {
		notionStatus := notion.LocalGoalStatusToNotion(status)
		if notionErr := s.notionTasks.UpdatePageProperties(ctx, *g.NotionPageID, map[string]any{
			"Status": map[string]any{"status": map[string]string{"name": notionStatus}},
		}); notionErr != nil {
			s.logger.Warn("update_goal_status: notion write-back failed", "goal", g.Title, "error", notionErr)
		}
	}

	return nil, UpdateGoalStatusOutput{
		Title:  updated.Title,
		Status: string(updated.Status),
		Area:   updated.Area,
	}, nil
}

func mapInputProjectStatus(s string) project.Status {
	switch s {
	case "Planned", "planned":
		return project.StatusPlanned
	case "Doing", "In Progress", "in-progress":
		return project.StatusInProgress
	case "On Hold", "on-hold":
		return project.StatusOnHold
	case "Ongoing", "maintained":
		return project.StatusMaintained
	case "Done", "Completed", "completed":
		return project.StatusCompleted
	case "Archived", "archived":
		return project.StatusArchived
	default:
		return project.StatusInProgress
	}
}

func mapInputGoalStatus(s string) goal.Status {
	switch s {
	case "Dream", "Not Started", "not-started":
		return goal.StatusNotStarted
	case "Active", "In Progress", "in-progress":
		return goal.StatusInProgress
	case "Achieved", "Done", "done":
		return goal.StatusDone
	case "Abandoned", "abandoned":
		return goal.StatusAbandoned
	default:
		return goal.StatusNotStarted
	}
}

func (s *Server) resolveTaskDBID(ctx context.Context) (string, error) {
	if s.taskDBResolver == nil {
		return "", fmt.Errorf("task database resolver not configured")
	}
	dbID, err := s.taskDBResolver.DatabaseIDByRole(ctx, "tasks")
	if err != nil {
		return "", fmt.Errorf("resolving tasks database id: %w", err)
	}
	return dbID, nil
}

// fetchRemainingMyDay returns My Day tasks that are still pending (excluding the just-completed task).
func (s *Server) fetchRemainingMyDay(ctx context.Context, excludeID uuid.UUID) []myDayRemaining {
	allTasks, err := s.tasks.PendingTasksWithProject(ctx, nil, 50)
	if err != nil {
		s.logger.Error("complete_task: fetching remaining my day", "error", err)
		return []myDayRemaining{}
	}
	remaining := make([]myDayRemaining, 0)
	for i := range allTasks {
		t := &allTasks[i]
		if !t.MyDay || t.ID == excludeID {
			continue
		}
		remaining = append(remaining, myDayRemaining{
			TaskID:   t.ID.String(),
			Title:    t.Title,
			Project:  t.ProjectTitle,
			Priority: t.Priority,
			Energy:   t.Energy,
		})
	}
	return remaining
}

func (s *Server) resolveProject(ctx context.Context, input string) (*project.Project, error) {
	proj, err := s.projects.ProjectBySlug(ctx, input)
	if err == nil {
		return proj, nil
	}
	proj, err = s.projects.ProjectByAlias(ctx, input)
	if err == nil {
		return proj, nil
	}
	proj, err = s.projects.ProjectByTitle(ctx, input)
	if err == nil {
		return proj, nil
	}
	return nil, fmt.Errorf("project %q not found", input)
}

func mapInputTaskStatus(s string) task.Status {
	switch s {
	case "To Do", "todo":
		return task.StatusTodo
	case "Doing", "In Progress", "in-progress":
		return task.StatusInProgress
	case "Done", "done":
		return task.StatusDone
	default:
		return task.StatusTodo
	}
}

// validEnergy checks if the energy value is valid for Notion (High or Low only).
func validEnergy(e string) bool {
	return e == "" || e == "High" || e == "Low"
}

func joinLines(lines []string) string {
	var b []byte
	for i, l := range lines {
		if i > 0 {
			b = append(b, '\n')
		}
		b = append(b, l...)
	}
	return string(b)
}

// buildNotionTaskProps builds a Notion properties map from changed task fields.
// Only includes properties that were explicitly set in the input (non-nil pointers).
// Project relation is handled separately by the caller (needs NotionPageID resolution).
func buildNotionTaskProps(input *UpdateTaskInput) map[string]any {
	props := make(map[string]any)
	if input.NewTitle != nil {
		props["Task Name"] = map[string]any{
			"title": []map[string]any{
				{"text": map[string]string{"content": *input.NewTitle}},
			},
		}
	}
	if input.Status != nil {
		props["Status"] = map[string]any{
			"status": map[string]string{"name": notion.NotionTaskStatusFromInput(*input.Status)},
		}
	}
	if input.Due != nil {
		if *input.Due == "" {
			props["Due"] = map[string]any{"date": nil}
		} else {
			props["Due"] = map[string]any{"date": map[string]string{"start": *input.Due}}
		}
	}
	if input.Priority != nil {
		if *input.Priority == "" {
			props["Priority"] = map[string]any{"status": nil}
		} else {
			props["Priority"] = map[string]any{"status": map[string]string{"name": *input.Priority}}
		}
	}
	if input.Energy != nil {
		if *input.Energy == "" {
			props["Energy"] = map[string]any{"select": nil}
		} else {
			props["Energy"] = map[string]any{"select": map[string]string{"name": *input.Energy}}
		}
	}
	if input.MyDay != nil {
		props["My Day"] = map[string]any{"checkbox": *input.MyDay}
	}
	return props
}
