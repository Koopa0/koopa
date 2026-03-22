package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/session"
)

// SessionDeltaInput is the input for the get_session_delta tool.
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
	InsightsChanged    []insightDelta     `json:"insights_changed"`
	SessionNotes       []sessionNoteBrief `json:"session_notes"`
	MetricsTrend       *metricsTrendBrief `json:"metrics_trend,omitempty"`
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
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	// Resolve since date
	var since time.Time
	if input.Since != "" {
		var err error
		since, err = time.Parse(time.DateOnly, input.Since)
		if err != nil {
			return nil, SessionDeltaOutput{}, fmt.Errorf("invalid date format: %s (expected YYYY-MM-DD)", input.Since)
		}
	} else if s.sessionReader != nil {
		lastNote, err := s.sessionReader.LatestNoteBySource(ctx, "claude")
		if err == nil {
			since = time.Date(lastNote.NoteDate.Year(), lastNote.NoteDate.Month(), lastNote.NoteDate.Day(), 0, 0, 0, 0, lastNote.NoteDate.Location())
		}
	}
	if since.IsZero() {
		since = today.AddDate(0, 0, -3)
	}

	out := SessionDeltaOutput{
		Period: deltaPeriod{
			From: since.Format(time.DateOnly),
			To:   today.Format(time.DateOnly),
			Days: int(today.Sub(since).Hours() / 24),
		},
	}

	// Tasks completed since
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

	// Tasks created since
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

	// Tasks became overdue (due between since and today, still pending)
	allPending, err := s.tasks.PendingTasksWithProject(ctx, nil, 100)
	if err != nil {
		s.logger.Error("session_delta: pending tasks", "error", err)
	}
	out.TasksBecameOverdue = make([]deltaTask, 0)
	for _, t := range allPending {
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

	// Build logs
	buildLogs, err := s.contents.RecentByType(ctx, "build-log", since, 10)
	if err != nil {
		s.logger.Error("session_delta: build logs", "error", err)
	}
	out.BuildLogs = make([]buildLogBrief, 0, len(buildLogs))
	for _, c := range buildLogs {
		out.BuildLogs = append(out.BuildLogs, buildLogBrief{
			Slug:        c.Slug,
			Title:       c.Title,
			Project:     extractFrontmatter(c.Body, "project"),
			SessionType: extractFrontmatter(c.Body, "session_type"),
			CreatedAt:   c.CreatedAt.Format(time.DateOnly),
		})
	}

	// Insights changed since
	if s.sessionReader != nil {
		insightNotes, insightErr := s.sessionReader.InsightsSince(ctx, since)
		if insightErr != nil && !errors.Is(insightErr, session.ErrNotFound) {
			s.logger.Error("session_delta: insights", "error", insightErr)
		}
		out.InsightsChanged = make([]insightDelta, 0, len(insightNotes))
		for _, n := range insightNotes {
			id := parseInsightDelta(&n)
			out.InsightsChanged = append(out.InsightsChanged, id)
		}

		// Session notes since
		notes, notesErr := s.sessionReader.NotesByDate(ctx, since, today, nil)
		if notesErr != nil {
			s.logger.Error("session_delta: session notes", "error", notesErr)
		}
		out.SessionNotes = make([]sessionNoteBrief, 0, len(notes))
		for _, n := range notes {
			excerpt := n.Content
			if len(excerpt) > 150 {
				excerpt = excerpt[:150] + "..."
			}
			out.SessionNotes = append(out.SessionNotes, sessionNoteBrief{
				Date:    n.NoteDate.Format(time.DateOnly),
				Type:    n.NoteType,
				Source:  n.Source,
				Excerpt: excerpt,
			})
		}

		// Metrics trend since
		metricsNotes, metricsErr := s.sessionReader.MetricsHistory(ctx, since)
		if metricsErr != nil {
			s.logger.Error("session_delta: metrics", "error", metricsErr)
		}
		if len(metricsNotes) > 0 {
			var totalRate float64
			for _, n := range metricsNotes {
				if dm := parseDailyMetrics(n); dm != nil {
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

	return nil, out, nil
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

// buildDailyMetricsList parses all metrics notes into dailyMetrics entries.
func buildDailyMetricsList(notes []session.Note) []dailyMetrics {
	entries := make([]dailyMetrics, 0, len(notes))
	for _, n := range notes {
		if dm := parseDailyMetrics(n); dm != nil {
			entries = append(entries, *dm)
		}
	}
	return entries
}
