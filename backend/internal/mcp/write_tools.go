package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/project"
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
	TaskID         string  `json:"task_id"`
	Title          string  `json:"title"`
	Project        string  `json:"project,omitempty"`
	CompletedAt    string  `json:"completed_at"`
	IsRecurring    bool    `json:"is_recurring"`
	NextRecurrence *string `json:"next_recurrence,omitempty"`
	Warning        string  `json:"warning,omitempty"`
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
	if t.CompletedAt != nil && t.CompletedAt.Format(time.DateOnly) == time.Now().Format(time.DateOnly) {
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

func (s *Server) createTask(ctx context.Context, _ *mcp.CallToolRequest, input CreateTaskInput) (*mcp.CallToolResult, CreateTaskOutput, error) {
	if input.Title == "" {
		return nil, CreateTaskOutput{}, fmt.Errorf("title is required")
	}

	if s.notionTasks == nil {
		return nil, CreateTaskOutput{}, fmt.Errorf("notion task writer not configured")
	}

	taskDBID, err := s.resolveTaskDBID(ctx)
	if err != nil {
		return nil, CreateTaskOutput{}, err
	}

	// Create in Notion (webhook will sync back to local DB)
	pageID, err := s.notionTasks.CreateTask(ctx, NotionCreateTaskParams{
		DatabaseID:  taskDBID,
		Title:       input.Title,
		DueDate:     input.Due,
		Description: input.Notes,
	})
	if err != nil {
		return nil, CreateTaskOutput{}, fmt.Errorf("creating notion task: %w", err)
	}

	out := CreateTaskOutput{
		TaskID: pageID,
		Title:  input.Title,
		Due:    input.Due,
	}

	// Resolve project name for output
	if input.Project != "" {
		proj, projErr := s.resolveProject(ctx, input.Project)
		if projErr != nil {
			out.Warning = fmt.Sprintf("task created but project %q not found", input.Project)
		} else {
			out.Project = proj.Title
		}
	}

	s.logger.Info("task created via mcp",
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

func (s *Server) updateTask(ctx context.Context, _ *mcp.CallToolRequest, input UpdateTaskInput) (*mcp.CallToolResult, UpdateTaskOutput, error) {
	if input.TaskID == "" && input.TaskTitle == "" {
		return nil, UpdateTaskOutput{}, fmt.Errorf("either task_id or task_title is required")
	}

	t, err := s.resolveTask(ctx, input.TaskID, input.TaskTitle)
	if err != nil {
		return nil, UpdateTaskOutput{}, err
	}

	params := task.UpdateParams{ID: t.ID}

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
	if input.Project != nil {
		proj, projErr := s.resolveProject(ctx, *input.Project)
		if projErr == nil {
			params.ProjectID = &proj.ID
		}
	}

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
	if len(input.TaskIDs) == 0 {
		return nil, BatchMyDayOutput{}, fmt.Errorf("task_ids is required")
	}

	var out BatchMyDayOutput

	if input.Clear {
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
	}

	return nil, out, nil
}

// --- log_learning_session ---

// LogLearningSessionInput is the input for the log_learning_session tool.
type LogLearningSessionInput struct {
	Topic      string   `json:"topic" jsonschema_description:"what was learned (required)"`
	Source     string   `json:"source" jsonschema_description:"leetcode, hackerrank, oreilly, ardanlabs, article, discussion (required)"`
	Title      string   `json:"title" jsonschema_description:"short title (required)"`
	Body       string   `json:"body" jsonschema_description:"markdown content: approach, concepts, insights (required)"`
	Tags       []string `json:"tags,omitempty" jsonschema_description:"tags for categorization"`
	Project    string   `json:"project,omitempty" jsonschema_description:"related project"`
	Difficulty string   `json:"difficulty,omitempty" jsonschema_description:"easy, medium, or hard"`
	ProblemURL string   `json:"problem_url,omitempty" jsonschema_description:"problem link"`
}

// LogLearningSessionOutput is the output of the log_learning_session tool.
type LogLearningSessionOutput struct {
	ContentID string `json:"content_id"`
	Slug      string `json:"slug"`
	Title     string `json:"title"`
	Status    string `json:"status"`
}

func (s *Server) logLearningSession(ctx context.Context, _ *mcp.CallToolRequest, input LogLearningSessionInput) (*mcp.CallToolResult, LogLearningSessionOutput, error) {
	if input.Topic == "" {
		return nil, LogLearningSessionOutput{}, fmt.Errorf("topic is required")
	}
	if input.Title == "" {
		return nil, LogLearningSessionOutput{}, fmt.Errorf("title is required")
	}
	if input.Body == "" {
		return nil, LogLearningSessionOutput{}, fmt.Errorf("body is required")
	}
	if input.Source == "" {
		input.Source = "discussion"
	}

	now := time.Now()
	topicSlug := Slugify(input.Topic)
	slug := fmt.Sprintf("%s-til-%s", topicSlug, now.Format("2006-01-02"))
	source := fmt.Sprintf("claude:%s", input.Source)
	sourceType := content.SourceAIGenerated

	tags := input.Tags
	if tags == nil {
		tags = []string{}
	}

	// Add metadata to body if provided
	body := input.Body
	if input.ProblemURL != "" {
		body = fmt.Sprintf("**Problem**: %s\n\n%s", input.ProblemURL, body)
	}
	if input.Difficulty != "" {
		body = fmt.Sprintf("**Difficulty**: %s\n\n%s", input.Difficulty, body)
	}

	created, err := s.contentWriter.CreateContent(ctx, content.CreateParams{
		Slug:        slug,
		Title:       input.Title,
		Body:        body,
		Type:        content.TypeTIL,
		Status:      content.StatusPublished,
		Tags:        tags,
		Source:      &source,
		SourceType:  &sourceType,
		ReviewLevel: content.ReviewAuto,
	})
	if err != nil {
		if errors.Is(err, content.ErrConflict) {
			slug = fmt.Sprintf("%s-til-%s-%d", topicSlug, now.Format("2006-01-02"), now.Unix()%10000)
			created, err = s.contentWriter.CreateContent(ctx, content.CreateParams{
				Slug:        slug,
				Title:       input.Title,
				Body:        body,
				Type:        content.TypeTIL,
				Status:      content.StatusPublished,
				Tags:        tags,
				Source:      &source,
				SourceType:  &sourceType,
				ReviewLevel: content.ReviewAuto,
			})
			if err != nil {
				return nil, LogLearningSessionOutput{}, fmt.Errorf("creating learning session: %w", err)
			}
		} else {
			return nil, LogLearningSessionOutput{}, fmt.Errorf("creating learning session: %w", err)
		}
	}

	s.logger.Info("learning session logged",
		"content_id", created.ID,
		"topic", input.Topic,
		"source", input.Source,
	)

	return nil, LogLearningSessionOutput{
		ContentID: created.ID.String(),
		Slug:      created.Slug,
		Title:     created.Title,
		Status:    string(created.Status),
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
		for i, m := range matches {
			titles[i] = fmt.Sprintf("- %s (id: %s)", m.Title, m.ID)
		}
		return nil, fmt.Errorf("ambiguous: %d tasks match %q, please specify task_id:\n%s",
			len(matches), taskTitle, joinLines(titles))
	}
	return &matches[0], nil
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

// Slugify converts a title to a URL-safe slug. Duplicated from notion package
// to avoid circular imports — this is a pure function with no dependencies.
func Slugify(title string) string {
	var result []rune
	prevDash := false
	for _, r := range title {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			result = append(result, r)
			prevDash = false
		case r >= 'A' && r <= 'Z':
			result = append(result, r+32) // lowercase
			prevDash = false
		case r == '-' || r == '_' || r == ' ':
			if !prevDash && len(result) > 0 {
				result = append(result, '-')
				prevDash = true
			}
		case r > 127:
			result = append(result, r)
			prevDash = false
		}
	}
	if len(result) > 0 && result[len(result)-1] == '-' {
		result = result[:len(result)-1]
	}
	return string(result)
}
