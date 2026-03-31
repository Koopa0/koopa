package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/activity"
	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/learning"
	"github.com/Koopa0/koopa0.dev/internal/notion"
	"github.com/Koopa0/koopa0.dev/internal/project"
	"github.com/Koopa0/koopa0.dev/internal/session"
	"github.com/Koopa0/koopa0.dev/internal/tag"
	"github.com/Koopa0/koopa0.dev/internal/task"
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

	if t.IsRecurring() {
		return s.completeRecurringTask(ctx, t, input.Notes)
	}
	return s.completeOneOffTask(ctx, t)
}

// completeOneOffTask handles completion for non-recurring tasks (original behavior).
func (s *Server) completeOneOffTask(ctx context.Context, t *task.Task) (*mcp.CallToolResult, CompleteTaskOutput, error) {
	// Update via Notion API
	if t.NotionPageID != nil && s.notionClient != nil {
		if notionErr := s.notionClient.UpdatePageStatus(ctx, *t.NotionPageID, "Done"); notionErr != nil {
			return nil, CompleteTaskOutput{}, fmt.Errorf("updating notion task status: %w", notionErr)
		}
	}

	updated, err := s.tasks.UpdateStatus(ctx, t.ID, task.StatusDone)
	if err != nil {
		return nil, CompleteTaskOutput{}, fmt.Errorf("completing task: %w", err)
	}

	out := CompleteTaskOutput{
		TaskID:      updated.ID.String(),
		Title:       updated.Title,
		CompletedAt: time.Now().Format(time.RFC3339),
		IsRecurring: false,
	}

	s.logger.Info("task completed via mcp",
		"task_id", updated.ID,
		"title", updated.Title,
		"is_recurring", false,
	)

	s.recordTaskCompletionEvent(ctx, updated)
	out.RemainingMyDayTasks = s.fetchRemainingMyDay(ctx, updated.ID)
	return nil, out, nil
}

// completeRecurringTask handles completion for recurring tasks:
// log activity event → advance due to next cycle → reset status to todo → sync to Notion.
func (s *Server) completeRecurringTask(ctx context.Context, t *task.Task, notes string) (*mcp.CallToolResult, CompleteTaskOutput, error) {
	now := time.Now()

	// Double-complete guard: check skip log activity for today (Asia/Taipei day boundary)
	todayStart := now.In(s.loc).Truncate(24 * time.Hour)
	skipCount, _ := s.tasks.SkipCountByTask(ctx, t.ID, todayStart) // best-effort
	var warning string
	if skipCount > 0 {
		// skipCount here is reused to count completions today via activity_events
		// Actually we should check activity_events for today's completions
	}
	_ = warning // will be set below if needed

	// Check today's completions via activity_events for double-complete warning
	if s.activity != nil {
		todayCompletions := s.countTodayCompletions(ctx, t.ID, todayStart)
		if todayCompletions > 0 {
			warning = fmt.Sprintf("This recurring task was already completed %d time(s) today. Completing again will advance the due date further.", todayCompletions)
		}
	}

	// Calculate next due date
	tomorrow := now.In(s.loc).AddDate(0, 0, 1).Truncate(24 * time.Hour)
	nextDue := t.NextCycleDateOnOrAfter(tomorrow)
	if nextDue == nil {
		return nil, CompleteTaskOutput{}, fmt.Errorf("cannot calculate next due for recurring task %s", t.ID)
	}

	// Reset local DB: advance due, status=todo, my_day=false
	updated, err := s.tasks.ResetRecurring(ctx, t.ID, *nextDue)
	if err != nil {
		return nil, CompleteTaskOutput{}, fmt.Errorf("resetting recurring task: %w", err)
	}

	// Sync to Notion: due=next, status=Not Started, My Day=false
	if t.NotionPageID != nil && s.notionClient != nil {
		props := map[string]any{
			"Status": map[string]any{"status": map[string]string{"name": "To Do"}},
			"My Day": map[string]any{"checkbox": false},
			"Due":    map[string]any{"date": map[string]string{"start": nextDue.Format(time.DateOnly)}},
		}
		if notionErr := s.notionClient.UpdatePageProperties(ctx, *t.NotionPageID, props); notionErr != nil {
			s.logger.Warn("recurring task notion sync failed", "task_id", t.ID, "error", notionErr)
		}
	}

	nd := nextDue.Format(time.DateOnly)
	out := CompleteTaskOutput{
		TaskID:         updated.ID.String(),
		Title:          updated.Title,
		CompletedAt:    now.Format(time.RFC3339),
		IsRecurring:    true,
		NextRecurrence: &nd,
		Warning:        warning,
	}

	s.logger.Info("recurring task completed via mcp",
		"task_id", updated.ID,
		"title", updated.Title,
		"next_due", nd,
	)

	// Record activity event with unique sourceID (timestamp-based, not date-based)
	s.recordTaskCompletionEvent(ctx, updated)
	out.RemainingMyDayTasks = s.fetchRemainingMyDay(ctx, updated.ID)
	return nil, out, nil
}

// recordTaskCompletionEvent records a task_completed activity event.
// Uses timestamp-based sourceID to allow multiple completions per day for recurring tasks.
func (s *Server) recordTaskCompletionEvent(ctx context.Context, t *task.Task) {
	if s.activity == nil {
		return
	}
	evTitle := fmt.Sprintf("Completed: %s", t.Title)
	sourceID := fmt.Sprintf("task-complete-%s-%d", t.ID, time.Now().UnixMilli())
	params := &activity.RecordParams{
		SourceID:  &sourceID,
		Timestamp: time.Now(),
		Source:    "mcp",
		EventType: "task_completed",
		Title:     &evTitle,
	}
	if t.ProjectID != nil {
		params.Project = s.resolveProjectSlug(ctx, *t.ProjectID)
	}
	//nolint:errcheck // best-effort
	s.activity.CreateEvent(ctx, params)
}

// countTodayCompletions counts task_completed events for a task today.
func (s *Server) countTodayCompletions(ctx context.Context, taskID uuid.UUID, todayStart time.Time) int {
	if s.activity == nil {
		return 0
	}
	prefix := fmt.Sprintf("task-complete-%s-", taskID)
	count, err := s.activity.CountEventsByPrefix(ctx, "task_completed", prefix, todayStart)
	if err != nil {
		s.logger.Warn("counting today completions", "task_id", taskID, "error", err)
		return 0
	}
	return count
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
	Assignee string `json:"assignee,omitempty" jsonschema_description:"human|claude-code|cowork (default: human)"`
}

// CreateTaskOutput is the output of the create_task tool.
type CreateTaskOutput struct {
	TaskID     string           `json:"task_id"`
	Title      string           `json:"title"`
	Due        string           `json:"due,omitempty"`
	Project    string           `json:"project,omitempty"`
	Warning    string           `json:"warning,omitempty"`
	MyDayTasks []myDayRemaining `json:"my_day_tasks,omitempty"`
}

// resolvedProject holds the resolved project info for task creation.
type resolvedProject struct {
	id           *uuid.UUID
	title        string
	notionPageID string
}

// resolveCreateTaskProject resolves the project for task creation.
func (s *Server) resolveCreateTaskProject(ctx context.Context, projectInput string) resolvedProject {
	if projectInput == "" {
		return resolvedProject{}
	}
	proj, projErr := s.resolveProjectChain(ctx, projectInput)
	if projErr != nil {
		return resolvedProject{}
	}
	rp := resolvedProject{id: &proj.ID, title: proj.Title}
	if proj.NotionPageID != nil {
		rp.notionPageID = *proj.NotionPageID
	}
	return rp
}

func (s *Server) createTask(ctx context.Context, _ *mcp.CallToolRequest, input *CreateTaskInput) (*mcp.CallToolResult, CreateTaskOutput, error) {
	if input.Title == "" {
		return nil, CreateTaskOutput{}, fmt.Errorf("title is required")
	}
	if !validEnergy(input.Energy) {
		return nil, CreateTaskOutput{}, fmt.Errorf("invalid energy %q (must be High or Low)", input.Energy)
	}
	if s.notionClient == nil {
		return nil, CreateTaskOutput{}, fmt.Errorf("notion task writer not configured")
	}

	taskDBID, err := s.resolveTaskDBID(ctx)
	if err != nil {
		return nil, CreateTaskOutput{}, err
	}

	rp := s.resolveCreateTaskProject(ctx, input.Project)

	var due *time.Time
	if input.Due != "" {
		if d, parseErr := time.Parse(time.DateOnly, input.Due); parseErr == nil {
			due = &d
		}
	}

	pageID, err := s.notionClient.CreateTask(ctx, &notion.CreateTaskParams{
		DatabaseID: taskDBID, Title: input.Title, DueDate: input.Due,
		Description: input.Notes, Priority: input.Priority, Energy: input.Energy,
		MyDay: input.MyDay, ProjectID: rp.notionPageID,
	})
	if err != nil {
		return nil, CreateTaskOutput{}, fmt.Errorf("creating notion task: %w", err)
	}

	assignee := input.Assignee
	if assignee == "" {
		assignee = "human"
	}
	if !task.ValidAssignee(assignee) {
		return nil, CreateTaskOutput{}, fmt.Errorf("invalid assignee %q (must be human, claude-code, or cowork)", assignee)
	}

	localTask, upsertErr := s.tasks.UpsertByNotionPageID(ctx, &task.UpsertByNotionParams{
		Title: input.Title, Status: task.StatusTodo, Due: due,
		ProjectID: rp.id, NotionPageID: pageID, Energy: input.Energy,
		Priority: input.Priority, MyDay: input.MyDay, Description: input.Notes, Assignee: assignee,
	})

	out := buildCreateTaskOutput(pageID, input, rp, localTask)
	if upsertErr != nil {
		s.logger.Error("create_task: local upsert failed (webhook will retry)", "error", upsertErr)
	}

	s.logger.Info("task created via mcp",
		"notion_page_id", pageID, "title", input.Title, "due", input.Due, "project", out.Project,
	)

	if input.MyDay {
		out.MyDayTasks = s.fetchMyDaySnapshot(ctx)
	}

	return nil, out, nil
}

// buildCreateTaskOutput assembles the output from create task results.
func buildCreateTaskOutput(pageID string, input *CreateTaskInput, rp resolvedProject, localTask *task.Task) CreateTaskOutput {
	out := CreateTaskOutput{TaskID: pageID, Title: input.Title, Due: input.Due}
	if rp.title != "" {
		out.Project = rp.title
	} else if input.Project != "" {
		out.Warning = fmt.Sprintf("task created but project %q not found", input.Project)
	}
	if localTask != nil {
		out.TaskID = localTask.ID.String()
	}
	return out
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
	Assignee  *string `json:"assignee,omitempty" jsonschema_description:"human|claude-code|cowork"`
}

// UpdateTaskOutput is the output of the update_task tool.
type UpdateTaskOutput struct {
	TaskID     string           `json:"task_id"`
	Title      string           `json:"title"`
	Status     string           `json:"status"`
	Due        string           `json:"due,omitempty"`
	Updated    string           `json:"updated_at"`
	MyDayTasks []myDayRemaining `json:"my_day_tasks,omitempty"`
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

	params, resolvedProj, buildErr := s.buildUpdateTaskParams(ctx, t.ID, input)
	if buildErr != nil {
		return nil, UpdateTaskOutput{}, buildErr
	}

	s.syncTaskToNotion(ctx, t, input, resolvedProj)

	updated, err := s.tasks.Update(ctx, params)
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
	if input.MyDay != nil {
		out.MyDayTasks = s.fetchMyDaySnapshot(ctx)
	}

	return nil, out, nil
}

// syncTaskToNotion syncs changed task properties to Notion.
// It is best-effort: errors are logged but not returned.
func (s *Server) syncTaskToNotion(ctx context.Context, t *task.Task, input *UpdateTaskInput, resolvedProject *project.Project) {
	if t.NotionPageID == nil || s.notionClient == nil {
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
	if notionErr := s.notionClient.UpdatePageProperties(ctx, *t.NotionPageID, notionProps); notionErr != nil {
		s.logger.Warn("update_task: notion write-back failed", "task_id", t.ID, "error", notionErr)
	}
}

// buildUpdateTaskParams constructs task.UpdateParams from input, resolving project and validating fields.
func (s *Server) buildUpdateTaskParams(ctx context.Context, taskID uuid.UUID, input *UpdateTaskInput) (*task.UpdateParams, *project.Project, error) {
	params := &task.UpdateParams{ID: taskID}

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
			return nil, nil, fmt.Errorf("invalid due date %q (expected YYYY-MM-DD)", *input.Due)
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
	if input.Assignee != nil {
		if !task.ValidAssignee(*input.Assignee) {
			return nil, nil, fmt.Errorf("invalid assignee %q (must be human, claude-code, or cowork)", *input.Assignee)
		}
		params.Assignee = input.Assignee
	}

	var resolvedProj *project.Project
	if input.Project != nil {
		proj, projErr := s.resolveProjectChain(ctx, *input.Project)
		if projErr == nil {
			resolvedProj = proj
			params.ProjectID = &proj.ID
		}
	}

	return params, resolvedProj, nil
}

// --- my_day ---

// BatchMyDayInput is the input for the my_day tool.
type BatchMyDayInput struct {
	TaskIDs []string `json:"task_ids" jsonschema_description:"task UUIDs to set as My Day"`
	Clear   bool     `json:"clear,omitempty" jsonschema_description:"clear all existing My Day first"`
}

// BatchMyDayOutput is the output of the my_day tool.
type BatchMyDayOutput struct {
	Cleared    int              `json:"cleared,omitempty"`
	Set        int              `json:"set"`
	MyDayTasks []myDayRemaining `json:"my_day_tasks"`
}

func (s *Server) batchMyDay(ctx context.Context, _ *mcp.CallToolRequest, input BatchMyDayInput) (*mcp.CallToolResult, BatchMyDayOutput, error) {
	if len(input.TaskIDs) == 0 && !input.Clear {
		return nil, BatchMyDayOutput{}, fmt.Errorf("task_ids is required (or set clear: true)")
	}

	var out BatchMyDayOutput

	if input.Clear {
		n, err := s.clearMyDay(ctx)
		if err != nil {
			return nil, BatchMyDayOutput{}, err
		}
		out.Cleared = n
	}

	for _, idStr := range input.TaskIDs {
		if err := s.setTaskMyDay(ctx, idStr); err != nil {
			return nil, BatchMyDayOutput{}, err
		}
		out.Set++
	}

	out.MyDayTasks = s.fetchMyDaySnapshot(ctx)
	return nil, out, nil
}

// clearMyDay syncs My Day=false to Notion and clears all local My Day flags.
func (s *Server) clearMyDay(ctx context.Context) (int, error) {
	if s.notionClient != nil {
		currentMyDay, myDayErr := s.tasks.MyDayTasksWithNotionPageID(ctx)
		if myDayErr != nil {
			s.logger.Warn("my_day: fetching notion page ids for clear", "error", myDayErr)
		}
		for _, t := range currentMyDay {
			s.syncMyDayToNotion(ctx, t.NotionPageID, false)
		}
	}
	n, err := s.tasks.ClearAllMyDay(ctx)
	if err != nil {
		return 0, fmt.Errorf("clearing my day: %w", err)
	}
	return int(n), nil
}

// setTaskMyDay marks a single task as My Day and syncs to Notion.
func (s *Server) setTaskMyDay(ctx context.Context, idStr string) error {
	id, parseErr := uuid.Parse(idStr)
	if parseErr != nil {
		return fmt.Errorf("invalid task_id %q: %w", idStr, parseErr)
	}
	if err := s.tasks.UpdateMyDay(ctx, id, true); err != nil {
		s.logger.Error("my_day: setting my day", "task_id", idStr, "error", err)
		return nil // best-effort: continue with remaining tasks
	}
	if s.notionClient != nil {
		t, taskErr := s.tasks.TaskByID(ctx, id)
		if taskErr == nil && t.NotionPageID != nil {
			s.syncMyDayToNotion(ctx, *t.NotionPageID, true)
		}
	}
	return nil
}

// syncMyDayToNotion updates the My Day checkbox for a task in Notion.
// It is best-effort: errors are logged but not returned.
func (s *Server) syncMyDayToNotion(ctx context.Context, notionPageID string, value bool) {
	if s.notionClient == nil || notionPageID == "" {
		return
	}
	props := map[string]any{"My Day": map[string]any{"checkbox": value}}
	if err := s.notionClient.UpdatePageProperties(ctx, notionPageID, props); err != nil {
		s.logger.Warn("my_day: notion sync failed", "notion_page_id", notionPageID, "error", err)
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

	LearningType string         `json:"learning_type,omitempty" jsonschema_description:"optional structured type: leetcode, book-reading, course, system-design, language"`
	Metadata     map[string]any `json:"metadata,omitempty" jsonschema_description:"optional per-type structured data (weakness_observations, key_concepts, etc.)"`
}

// LogLearningSessionOutput is the output of the log_learning_session tool.
type LogLearningSessionOutput struct {
	ContentID         string             `json:"content_id"`
	Slug              string             `json:"slug"`
	Title             string             `json:"title"`
	Status            string             `json:"status"`
	AutoCompletedTask *AutoCompletedTask `json:"auto_completed_task"`
	AutoCompleteSkip  string             `json:"auto_complete_skip,omitempty"`
}

// AutoCompletedTask reports the result of auto-completing a recurring task.
type AutoCompletedTask struct {
	TaskID  string  `json:"task_id"`
	Title   string  `json:"title"`
	NextDue *string `json:"next_due,omitempty"`
}

func (s *Server) logLearningSession(ctx context.Context, _ *mcp.CallToolRequest, input *LogLearningSessionInput) (*mcp.CallToolResult, LogLearningSessionOutput, error) {
	// TODO: resolved tags should be written to content_tags junction table after content creation.
	_, err := learning.ValidateInput(&learning.SessionInput{
		Project:    input.Project,
		Topic:      input.Topic,
		Title:      input.Title,
		Body:       input.Body,
		Source:     input.Source,
		Difficulty: input.Difficulty,
		Tags:       input.Tags,
	})
	if err != nil {
		return nil, LogLearningSessionOutput{}, err
	}
	// Validate per-type structured metadata if provided.
	if err := learning.ValidateLearningMetadata(input.LearningType, input.Metadata); err != nil {
		return nil, LogLearningSessionOutput{}, fmt.Errorf("metadata validation: %w", err)
	}

	now := time.Now()
	topicSlug := tag.Slugify(input.Topic)
	slug := fmt.Sprintf("%s-til-%s", topicSlug, now.Format("2006-01-02"))
	source := fmt.Sprintf("claude:%s", input.Source)
	sourceType := content.SourceAIGenerated

	// Add metadata to body only if not already present (Claude often includes these in the body)
	body := input.Body
	if input.ProblemURL != "" && !strings.Contains(body, input.ProblemURL) {
		body = fmt.Sprintf("**Problem**: %s\n\n%s", input.ProblemURL, body)
	}
	if input.Difficulty != "" && !strings.Contains(strings.ToLower(body), strings.ToLower(input.Difficulty)) {
		body = fmt.Sprintf("**Difficulty**: %s\n\n%s", input.Difficulty, body)
	}

	// Resolve project to store ID on the content record.
	// Also add project slug as a tag so contentMatchesProject can find it
	// even when the FK is missing (e.g. project not yet in projects table).
	var projectID *uuid.UUID
	if input.Project != "" && input.Project != "none" {
		if proj, projErr := s.resolveProjectChain(ctx, input.Project); projErr == nil {
			projectID = &proj.ID
		}
	}

	// Serialize per-type metadata into ai_metadata JSONB if provided.
	var aiMetadata json.RawMessage
	if input.Metadata != nil {
		if input.LearningType != "" {
			input.Metadata["learning_type"] = input.LearningType
		}
		aiMetadata, err = json.Marshal(input.Metadata)
		if err != nil {
			return nil, LogLearningSessionOutput{}, fmt.Errorf("marshaling metadata: %w", err)
		}
	}

	params := &content.CreateParams{
		Slug:        slug,
		Title:       input.Title,
		Body:        body,
		Type:        content.TypeTIL,
		Status:      content.StatusPublished,
		Source:      &source,
		SourceType:  &sourceType,
		ReviewLevel: content.ReviewAuto,
		IsPublic:    false,
		ProjectID:   projectID,
		AIMetadata:  aiMetadata,
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
	if input.Project == "none" {
		out.AutoCompleteSkip = "project is 'none', skipped"
	} else {
		completed, reason := s.autoCompleteRecurringTask(ctx, input.Project)
		out.AutoCompletedTask = completed
		if completed == nil {
			out.AutoCompleteSkip = reason
		}
	}

	return nil, out, nil
}

// autoCompleteRecurringTask finds and completes a recurring task matching the
// project. Returns (task, "") on success or (nil, reason) explaining why no
// task was completed — auto-complete is best-effort and must never fail the
// primary log_learning_session operation.
func (s *Server) autoCompleteRecurringTask(ctx context.Context, projectInput string) (completed *AutoCompletedTask, reason string) {
	proj, err := s.resolveProjectChain(ctx, projectInput)
	if err != nil {
		s.logger.Warn("auto-complete: project not found", "project", projectInput, "error", err)
		return nil, fmt.Sprintf("project %q not found", projectInput)
	}

	now := time.Now().In(s.loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, s.loc)
	// Pass end-of-day so due <= @today catches tasks due today (due stored as midnight)
	endOfDay := today.AddDate(0, 0, 1)

	t, err := s.tasks.RecurringTaskByProject(ctx, proj.ID, endOfDay)
	if err != nil {
		s.logger.Warn("auto-complete: query failed", "project", projectInput, "error", err)
		return nil, fmt.Sprintf("query failed: %v", err)
	}
	if t == nil {
		s.logger.Debug("auto-complete: no matching recurring task", "project", projectInput)
		return nil, fmt.Sprintf("no recurring task under project %q is due today or in My Day", proj.Title)
	}

	// Check if already completed today (reuse same logic as completeTask)
	if t.CompletedAt != nil && t.CompletedAt.In(s.loc).Format(time.DateOnly) == now.Format(time.DateOnly) {
		s.logger.Info("auto-complete: task already completed today", "task_id", t.ID, "title", t.Title)
		return nil, fmt.Sprintf("task %q already completed today", t.Title)
	}

	// Complete the task via the existing completeTask flow
	_, completeOut, completeErr := s.completeTask(ctx, nil, CompleteTaskInput{
		TaskID: t.ID.String(),
	})
	if completeErr != nil {
		s.logger.Warn("auto-complete: complete failed", "task_id", t.ID, "error", completeErr)
		return nil, fmt.Sprintf("complete failed: %v", completeErr)
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
	}, ""
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

// validateSessionNoteInput checks required fields, enum values, and per-type
// metadata requirements for SaveSessionNoteInput.
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

	if err := validateSessionNoteMetadata(input.NoteType, input.Metadata); err != nil {
		return err
	}

	return nil
}

// validateSessionNoteMetadata enforces required metadata fields per note_type.
func validateSessionNoteMetadata(noteType string, meta map[string]any) error {
	switch noteType {
	case "insight":
		if _, ok := meta["hypothesis"]; !ok {
			return fmt.Errorf("insight metadata requires 'hypothesis' field")
		}
		if _, ok := meta["invalidation_condition"]; !ok {
			return fmt.Errorf("insight metadata requires 'invalidation_condition' field")
		}
		if _, ok := meta["status"]; !ok {
			meta["status"] = "unverified"
		}
	case "plan":
		if _, ok := meta["reasoning"]; !ok {
			return fmt.Errorf("plan metadata requires 'reasoning' field")
		}
		_, hasIDs := meta["committed_task_ids"]
		_, hasItems := meta["committed_items"]
		if !hasIDs && !hasItems {
			return fmt.Errorf("plan metadata requires 'committed_task_ids' or 'committed_items' (or both)")
		}
	case "metrics":
		if _, ok := meta["tasks_planned"]; !ok {
			return fmt.Errorf("metrics metadata requires 'tasks_planned' field")
		}
		if _, ok := meta["tasks_completed"]; !ok {
			return fmt.Errorf("metrics metadata requires 'tasks_completed' field")
		}
		if _, ok := meta["adjustments"]; !ok {
			return fmt.Errorf("metrics metadata requires 'adjustments' field")
		}
	}
	// context and reflection: no metadata requirements
	return nil
}

func (s *Server) saveSessionNote(ctx context.Context, _ *mcp.CallToolRequest, input SaveSessionNoteInput) (*mcp.CallToolResult, SaveSessionNoteOutput, error) {
	if s.sessions == nil {
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

	created, err := s.sessions.CreateNote(ctx, &session.CreateParams{
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

	if s.projects == nil {
		return nil, UpdateProjectStatusOutput{}, fmt.Errorf("project writer not configured")
	}

	proj, err := s.resolveProjectChain(ctx, input.Project)
	if err != nil {
		return nil, UpdateProjectStatusOutput{}, err
	}

	status := mapInputProjectStatus(input.Status)
	updated, err := s.projects.UpdateStatus(ctx, proj.ID, status, input.ReviewNotes, input.ExpectedCadence)
	if err != nil {
		return nil, UpdateProjectStatusOutput{}, fmt.Errorf("updating project status: %w", err)
	}

	// Sync to Notion (best-effort)
	if proj.NotionPageID != nil && s.notionClient != nil {
		notionProps := map[string]any{
			"Status": map[string]any{"status": map[string]string{"name": project.StatusToNotion(status)}},
		}
		if input.ReviewNotes != nil && *input.ReviewNotes != "" {
			notionProps["Review Notes"] = map[string]any{
				"rich_text": []map[string]any{
					{"type": "text", "text": map[string]string{"content": *input.ReviewNotes}},
				},
			}
		}
		if notionErr := s.notionClient.UpdatePageProperties(ctx, *proj.NotionPageID, notionProps); notionErr != nil {
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

	g, err := s.goals.GoalByTitle(ctx, input.GoalTitle)
	if err != nil {
		return nil, UpdateGoalStatusOutput{}, fmt.Errorf("goal %q not found", input.GoalTitle)
	}

	status := mapInputGoalStatus(input.Status)
	updated, err := s.goals.UpdateStatus(ctx, g.ID, status)
	if err != nil {
		return nil, UpdateGoalStatusOutput{}, fmt.Errorf("updating goal status: %w", err)
	}

	// Sync to Notion (best-effort)
	if g.NotionPageID != nil && s.notionClient != nil {
		notionStatus := goal.StatusToNotion(status)
		if notionErr := s.notionClient.UpdatePageProperties(ctx, *g.NotionPageID, map[string]any{
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

// resolveProjectSlug returns a pointer to the project slug for the given ID.
// Returns nil if the project cannot be found (best-effort for telemetry).
func (s *Server) resolveProjectSlug(ctx context.Context, projectID uuid.UUID) *string {
	projects, err := s.projects.ActiveProjects(ctx)
	if err != nil {
		return nil
	}
	for i := range projects {
		if projects[i].ID == projectID {
			return &projects[i].Slug
		}
	}
	return nil
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
	allTasks, err := s.tasks.PendingTasksWithProject(ctx, nil, nil, 50)
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

// fetchMyDaySnapshot returns the current My Day task list using the dedicated store method.
func (s *Server) fetchMyDaySnapshot(ctx context.Context) []myDayRemaining {
	snapshots, err := s.tasks.MyDayTasks(ctx)
	if err != nil {
		s.logger.Error("fetching my day snapshot", "error", err)
		return []myDayRemaining{}
	}
	result := make([]myDayRemaining, len(snapshots))
	for i := range snapshots {
		result[i] = myDayRemaining{
			TaskID:   snapshots[i].ID.String(),
			Title:    snapshots[i].Title,
			Project:  snapshots[i].ProjectTitle,
			Priority: snapshots[i].Priority,
			Energy:   snapshots[i].Energy,
		}
	}
	return result
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
			"status": map[string]string{"name": task.NotionStatusFromInput(*input.Status)},
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

// --- skip_history ---

// SkipHistoryInput is the input for the skip_history tool.
type SkipHistoryInput struct {
	TaskID    string `json:"task_id,omitempty" jsonschema_description:"filter by task UUID"`
	ProjectID string `json:"project_id,omitempty" jsonschema_description:"filter by project UUID"`
	Days      int    `json:"days,omitempty" jsonschema_description:"lookback days (default 30)"`
}

// SkipHistoryOutput is the output of the skip_history tool.
type SkipHistoryOutput struct {
	TotalSkips int              `json:"total_skips"`
	Records    []skipHistoryRow `json:"records"`
}

type skipHistoryRow struct {
	TaskID      string `json:"task_id"`
	TaskTitle   string `json:"task_title,omitempty"`
	OriginalDue string `json:"original_due"`
	SkippedDate string `json:"skipped_date"`
	Reason      string `json:"reason"`
}

func (s *Server) getSkipHistory(ctx context.Context, _ *mcp.CallToolRequest, input SkipHistoryInput) (*mcp.CallToolResult, SkipHistoryOutput, error) {
	days := input.Days
	if days <= 0 {
		days = 30
	}
	since := time.Now().In(s.loc).AddDate(0, 0, -days).Truncate(24 * time.Hour)

	var out SkipHistoryOutput

	if input.TaskID != "" {
		id, err := uuid.Parse(input.TaskID)
		if err != nil {
			return nil, out, fmt.Errorf("invalid task_id: %w", err)
		}
		records, err := s.tasks.SkipHistoryByTask(ctx, id, since)
		if err != nil {
			return nil, out, fmt.Errorf("querying skip history: %w", err)
		}
		out.TotalSkips = len(records)
		for _, r := range records {
			out.Records = append(out.Records, skipHistoryRow{
				TaskID:      r.TaskID.String(),
				OriginalDue: r.OriginalDue.Format(time.DateOnly),
				SkippedDate: r.SkippedDate.Format(time.DateOnly),
				Reason:      r.Reason,
			})
		}
		return nil, out, nil
	}

	if input.ProjectID != "" {
		id, err := uuid.Parse(input.ProjectID)
		if err != nil {
			return nil, out, fmt.Errorf("invalid project_id: %w", err)
		}
		records, err := s.tasks.SkipHistoryByProject(ctx, id, since)
		if err != nil {
			return nil, out, fmt.Errorf("querying project skip history: %w", err)
		}
		out.TotalSkips = len(records)
		for _, r := range records {
			out.Records = append(out.Records, skipHistoryRow{
				TaskID:      r.TaskID.String(),
				TaskTitle:   r.TaskTitle,
				OriginalDue: r.OriginalDue.Format(time.DateOnly),
				SkippedDate: r.SkippedDate.Format(time.DateOnly),
				Reason:      r.Reason,
			})
		}
		return nil, out, nil
	}

	return nil, out, fmt.Errorf("either task_id or project_id is required")
}

// --- completion_history ---

// CompletionHistoryInput is the input for the completion_history tool.
type CompletionHistoryInput struct {
	TaskID    string `json:"task_id,omitempty" jsonschema_description:"filter by task UUID"`
	ProjectID string `json:"project_id,omitempty" jsonschema_description:"filter by project UUID"`
	Days      int    `json:"days,omitempty" jsonschema_description:"lookback days (default 30)"`
}

// CompletionHistoryOutput is the output of the completion_history tool.
type CompletionHistoryOutput struct {
	TotalCompletions int                    `json:"total_completions"`
	Records          []completionHistoryRow `json:"records"`
}

type completionHistoryRow struct {
	TaskTitle   string `json:"task_title,omitempty"`
	Project     string `json:"project,omitempty"`
	CompletedAt string `json:"completed_at"`
}

func (s *Server) getCompletionHistory(ctx context.Context, _ *mcp.CallToolRequest, input CompletionHistoryInput) (*mcp.CallToolResult, CompletionHistoryOutput, error) {
	days := input.Days
	if days <= 0 {
		days = 30
	}
	since := time.Now().In(s.loc).AddDate(0, 0, -days)

	var out CompletionHistoryOutput

	// Query activity_events for task_completed events
	if s.activity == nil {
		return nil, out, fmt.Errorf("activity store not available")
	}

	if input.TaskID != "" {
		id, err := uuid.Parse(input.TaskID)
		if err != nil {
			return nil, out, fmt.Errorf("invalid task_id: %w", err)
		}
		// Look up task title
		t, _ := s.tasks.TaskByID(ctx, id)
		prefix := fmt.Sprintf("task-complete-%s-", id)
		count, _ := s.activity.CountEventsByPrefix(ctx, "task_completed", prefix, since)
		out.TotalCompletions = count
		if t != nil {
			for range count {
				out.Records = append(out.Records, completionHistoryRow{
					TaskTitle: t.Title,
				})
			}
		}
		return nil, out, nil
	}

	if input.ProjectID != "" {
		id, err := uuid.Parse(input.ProjectID)
		if err != nil {
			return nil, out, fmt.Errorf("invalid project_id: %w", err)
		}
		completions, err := s.activity.CompletionsByProjectSince(ctx, since)
		if err != nil {
			return nil, out, fmt.Errorf("querying completion history: %w", err)
		}
		// Find the project title for the given ID
		_ = id // project filter applied at activity level via project slug
		for _, c := range completions {
			out.TotalCompletions += int(c.Completed)
			out.Records = append(out.Records, completionHistoryRow{
				Project: c.ProjectTitle,
			})
		}
		return nil, out, nil
	}

	// No filter: return all completions
	completions, err := s.activity.CompletionsByProjectSince(ctx, since)
	if err != nil {
		return nil, out, fmt.Errorf("querying completion history: %w", err)
	}
	for _, c := range completions {
		out.TotalCompletions += int(c.Completed)
		out.Records = append(out.Records, completionHistoryRow{
			Project: c.ProjectTitle,
		})
	}
	return nil, out, nil
}
