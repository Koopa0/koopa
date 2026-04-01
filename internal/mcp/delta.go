package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/session"
)

// SessionDeltaInput is the input for the session_delta tool.
type SessionDeltaInput struct {
	Since string `json:"since,omitempty" jsonschema_description:"ISO date YYYY-MM-DD. Default: date of last Claude.ai session note."`
}

// SessionDeltaOutput shows what changed since the last Claude.ai session.
type SessionDeltaOutput struct {
	Period             deltaPeriod        `json:"period"`
	TasksCompleted     []deltaTask        `json:"tasks_completed"`
	TasksCreated       []deltaTask        `json:"tasks_created"`
	TasksBecameOverdue []deltaTask        `json:"tasks_became_overdue"`
	BuildLogs          []buildLogBrief    `json:"build_logs"`
	ProjectChanges     []statusChange     `json:"project_changes"`
	GoalChanges        []statusChange     `json:"goal_changes"`
	InsightsChanged    []insightDelta     `json:"insights_changed"`
	SessionNotes       []sessionNoteBrief `json:"session_notes"`
	MetricsTrend       *metricsTrendBrief `json:"metrics_trend,omitempty"`
}

type statusChange struct {
	Title  string `json:"title"`
	Status string `json:"status"`
	Date   string `json:"date"`
	Source string `json:"source"`
}

type deltaPeriod struct {
	From string `json:"from"`
	To   string `json:"to"`
	Days int    `json:"days"`
}

type deltaTask struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Project string `json:"project,omitempty"`
	Date    string `json:"date"`
}

type insightDelta struct {
	ID            int64  `json:"id"`
	Hypothesis    string `json:"hypothesis"`
	CurrentStatus string `json:"current_status"`
	EvidenceCount int    `json:"evidence_count"`
}

type sessionNoteBrief struct {
	Date    string `json:"date"`
	Type    string `json:"type"`
	Source  string `json:"source"`
	Excerpt string `json:"excerpt"`
}

type metricsTrendBrief struct {
	AvgCompletionRate float64 `json:"avg_completion_rate"`
	Trend             string  `json:"trend"`
	DaysTracked       int     `json:"days_tracked"`
}

func (s *Server) getSessionDelta(ctx context.Context, _ *mcp.CallToolRequest, input SessionDeltaInput) (*mcp.CallToolResult, SessionDeltaOutput, error) {
	now := time.Now().In(s.loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, s.loc)

	since, err := s.resolveDeltaSince(ctx, input.Since, today)
	if err != nil {
		return nil, SessionDeltaOutput{}, err
	}

	out := SessionDeltaOutput{
		Period: deltaPeriod{
			From: since.Format(time.DateOnly),
			To:   today.Format(time.DateOnly),
			Days: int(today.Sub(since).Hours() / 24),
		},
	}

	s.fetchDeltaCompletedTasks(ctx, &out, since)
	s.fetchDeltaCreatedTasks(ctx, &out, since)
	s.fetchDeltaOverdueTasks(ctx, &out, since, today)
	s.fetchDeltaBuildLogs(ctx, &out, since)
	s.fetchDeltaStatusChanges(ctx, &out, since, today)
	s.fetchDeltaSessionData(ctx, &out, since, today)

	return nil, out, nil
}

// resolveDeltaSince determines the start date for the delta computation.
// Uses explicit input, falls back to last Claude session date, then defaults to 3 days ago.
func (s *Server) resolveDeltaSince(ctx context.Context, sinceInput string, today time.Time) (time.Time, error) {
	if sinceInput != "" {
		since, err := time.Parse(time.DateOnly, sinceInput)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid date format: %s (expected YYYY-MM-DD)", sinceInput)
		}
		return since, nil
	}

	if s.sessions != nil {
		lastNote, err := s.sessions.LatestNoteBySource(ctx, "claude")
		if err == nil {
			return time.Date(lastNote.NoteDate.Year(), lastNote.NoteDate.Month(), lastNote.NoteDate.Day(), 0, 0, 0, 0, lastNote.NoteDate.Location()), nil
		}
	}

	return today.AddDate(0, 0, -3), nil
}

// fetchDeltaCompletedTasks fetches tasks completed since the given date.
func (s *Server) fetchDeltaCompletedTasks(ctx context.Context, out *SessionDeltaOutput, since time.Time) {
	completed, err := s.tasks.CompletedTasksDetailSince(ctx, since)
	if err != nil {
		s.logger.Error("session_delta: completed tasks", "error", err)
	}
	out.TasksCompleted = make([]deltaTask, 0, len(completed))
	for _, t := range completed {
		dt := deltaTask{
			ID:      t.ID.String(),
			Title:   t.Title,
			Project: t.ProjectTitle,
		}
		if t.CompletedAt != nil {
			dt.Date = t.CompletedAt.Format(time.DateOnly)
		}
		out.TasksCompleted = append(out.TasksCompleted, dt)
	}
}

// fetchDeltaCreatedTasks fetches tasks created since the given date.
func (s *Server) fetchDeltaCreatedTasks(ctx context.Context, out *SessionDeltaOutput, since time.Time) {
	created, err := s.tasks.TasksCreatedSince(ctx, since)
	if err != nil {
		s.logger.Error("session_delta: created tasks", "error", err)
	}
	out.TasksCreated = make([]deltaTask, 0, len(created))
	for _, t := range created {
		out.TasksCreated = append(out.TasksCreated, deltaTask{
			ID:      t.ID.String(),
			Title:   t.Title,
			Project: t.ProjectTitle,
			Date:    t.CreatedAt.Format(time.DateOnly),
		})
	}
}

// fetchDeltaOverdueTasks finds pending tasks whose due date fell between since and today.
func (s *Server) fetchDeltaOverdueTasks(ctx context.Context, out *SessionDeltaOutput, since, today time.Time) {
	allPending, err := s.tasks.PendingTasksWithProject(ctx, nil, nil, 100)
	if err != nil {
		s.logger.Error("session_delta: pending tasks", "error", err)
	}
	out.TasksBecameOverdue = make([]deltaTask, 0)
	for tIdx := range allPending {
		t := &allPending[tIdx]
		if t.Due == nil {
			continue
		}
		dueDate := time.Date(t.Due.Year(), t.Due.Month(), t.Due.Day(), 0, 0, 0, 0, t.Due.Location())
		if !dueDate.Before(since) && dueDate.Before(today) {
			out.TasksBecameOverdue = append(out.TasksBecameOverdue, deltaTask{
				ID:      t.ID.String(),
				Title:   t.Title,
				Project: t.ProjectTitle,
				Date:    t.Due.Format(time.DateOnly),
			})
		}
	}
}

// fetchDeltaBuildLogs fetches build log content entries since the given date.
func (s *Server) fetchDeltaBuildLogs(ctx context.Context, out *SessionDeltaOutput, since time.Time) {
	buildLogs, err := s.contents.RecentByType(ctx, "build-log", since, 10)
	if err != nil {
		s.logger.Error("session_delta: build logs", "error", err)
	}
	out.BuildLogs = make([]buildLogBrief, 0, len(buildLogs))
	for cIdx := range buildLogs {
		c := &buildLogs[cIdx]
		out.BuildLogs = append(out.BuildLogs, buildLogBrief{
			Slug:        c.Slug,
			Title:       c.Title,
			Project:     extractFrontmatter(c.Body, "project"),
			SessionType: extractFrontmatter(c.Body, "session_type"),
			CreatedAt:   c.CreatedAt.Format(time.DateOnly),
		})
	}
}

// fetchDeltaSessionData fetches insights, session notes, and metrics trend since the given date.
func (s *Server) fetchDeltaSessionData(ctx context.Context, out *SessionDeltaOutput, since, today time.Time) {
	if s.sessions == nil {
		return
	}

	insightNotes, insightErr := s.sessions.InsightsSince(ctx, since)
	if insightErr != nil && !errors.Is(insightErr, session.ErrNotFound) {
		s.logger.Error("session_delta: insights", "error", insightErr)
	}
	out.InsightsChanged = make([]insightDelta, 0, len(insightNotes))
	for i := range insightNotes {
		out.InsightsChanged = append(out.InsightsChanged, parseInsightDelta(&insightNotes[i]))
	}

	notes, notesErr := s.sessions.NotesByDate(ctx, since, today, nil, nil)
	if notesErr != nil {
		s.logger.Error("session_delta: session notes", "error", notesErr)
	}
	out.SessionNotes = make([]sessionNoteBrief, 0, len(notes))
	for i := range notes {
		n := &notes[i]
		excerpt := truncate(n.Content, 150)
		out.SessionNotes = append(out.SessionNotes, sessionNoteBrief{
			Date:    n.NoteDate.Format(time.DateOnly),
			Type:    n.NoteType,
			Source:  n.Source,
			Excerpt: excerpt,
		})
	}

	metricsNotes, metricsErr := s.sessions.MetricsHistory(ctx, since)
	if metricsErr != nil {
		s.logger.Error("session_delta: metrics", "error", metricsErr)
	}
	if len(metricsNotes) > 0 {
		var totalRate float64
		for i := range metricsNotes {
			if dm := parseDailyMetrics(&metricsNotes[i]); dm != nil {
				totalRate += dm.CompletionRate
			}
		}
		out.MetricsTrend = &metricsTrendBrief{
			AvgCompletionRate: totalRate / float64(len(metricsNotes)),
			Trend:             computeTrend(buildDailyMetricsList(metricsNotes)),
			DaysTracked:       len(metricsNotes),
		}
	}
}

// parseInsightDelta extracts delta information from an insight session note.
func parseInsightDelta(n *session.Note) insightDelta {
	delta := insightDelta{ID: n.ID}
	if len(n.Metadata) == 0 {
		return delta
	}
	var meta struct {
		Hypothesis string   `json:"hypothesis"`
		Status     string   `json:"status"`
		Evidence   []string `json:"supporting_evidence"`
		LegacyEv   []string `json:"evidence"`
	}
	if err := json.Unmarshal(n.Metadata, &meta); err != nil {
		return delta
	}
	delta.Hypothesis = meta.Hypothesis
	delta.CurrentStatus = meta.Status
	delta.EvidenceCount = len(meta.Evidence)
	if delta.EvidenceCount == 0 {
		delta.EvidenceCount = len(meta.LegacyEv)
	}
	return delta
}

// fetchDeltaStatusChanges extracts project and goal status changes from activity events.
func (s *Server) fetchDeltaStatusChanges(ctx context.Context, out *SessionDeltaOutput, since, today time.Time) {
	events, err := s.activity.EventsByFilters(ctx, since, today, nil, nil, 200)
	if err != nil {
		s.logger.Error("session_delta: status changes", "error", err)
		return
	}

	out.ProjectChanges = make([]statusChange, 0)
	out.GoalChanges = make([]statusChange, 0)
	for i := range events {
		e := &events[i]
		if e.EventType != "project_update" && e.EventType != "goal_update" {
			continue
		}
		sc := statusChange{
			Date:   e.Timestamp.Format(time.DateOnly),
			Source: e.Source,
		}
		if e.Title != nil {
			sc.Title = *e.Title
		}
		// Extract status from metadata
		if len(e.Metadata) > 0 {
			var meta map[string]string
			if json.Unmarshal(e.Metadata, &meta) == nil {
				sc.Status = meta["status"]
			}
		}
		switch e.EventType {
		case "project_update":
			out.ProjectChanges = append(out.ProjectChanges, sc)
		case "goal_update":
			out.GoalChanges = append(out.GoalChanges, sc)
		}
	}
}

// buildDailyMetricsList parses all metrics notes into dailyMetrics entries.
func buildDailyMetricsList(notes []session.Note) []dailyMetrics {
	entries := make([]dailyMetrics, 0, len(notes))
	for i := range notes {
		if dm := parseDailyMetrics(&notes[i]); dm != nil {
			entries = append(entries, *dm)
		}
	}
	return entries
}
