// Package mcpserver provides an MCP (Model Context Protocol) server exposing
// tools for querying and managing the koopa0.dev knowledge engine.
package mcpserver

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/google/uuid"

	pgvector "github.com/pgvector/pgvector-go"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/session"
	"github.com/koopa0/blog-backend/internal/stats"
	"github.com/koopa0/blog-backend/internal/task"
)

// NoteSearcher provides note search and retrieval for MCP tools.
type NoteSearcher interface {
	SearchByText(ctx context.Context, query string, limit int) ([]note.SearchResult, error)
	SearchByFilters(ctx context.Context, f note.SearchFilter, limit int) ([]note.Note, error)
	NotesByType(ctx context.Context, noteType string, filterContext *string, limit int) ([]note.Note, error)
}

// NoteSemanticSearcher provides embedding-based semantic search for notes.
type NoteSemanticSearcher interface {
	SearchBySimilarity(ctx context.Context, queryVec pgvector.Vector, limit int) ([]note.SimilarityResult, error)
}

// QueryEmbedder generates an embedding vector for a search query string.
type QueryEmbedder interface {
	EmbedQuery(ctx context.Context, text string) (pgvector.Vector, error)
}

// ActivityReader provides activity event queries for MCP tools.
type ActivityReader interface {
	EventsByFilters(ctx context.Context, start, end time.Time, source, project *string, limit int) ([]activity.Event, error)
	EventsByProject(ctx context.Context, project string, limit int) ([]activity.Event, error)
}

// ProjectReader provides project lookup for MCP tools.
type ProjectReader interface {
	ProjectBySlug(ctx context.Context, slug string) (*project.Project, error)
	ProjectByAlias(ctx context.Context, alias string) (*project.Project, error)
	ProjectByTitle(ctx context.Context, title string) (*project.Project, error)
	ActiveProjects(ctx context.Context) ([]project.Project, error)
}

// CollectedReader provides recent collected data for MCP tools.
type CollectedReader interface {
	RecentCollectedData(ctx context.Context, start, end time.Time, limit int32) ([]collected.CollectedData, error)
}

// StatsReader provides platform statistics for MCP tools.
type StatsReader interface {
	Overview(ctx context.Context) (*stats.Overview, error)
	Drift(ctx context.Context, days int) (*stats.DriftReport, error)
	Learning(ctx context.Context) (*stats.LearningDashboard, error)
}

// TaskReader provides task queries for MCP tools.
type TaskReader interface {
	PendingTasksWithProject(ctx context.Context, projectSlug *string, limit int32) ([]task.PendingTaskDetail, error)
	TaskByID(ctx context.Context, id uuid.UUID) (*task.Task, error)
	PendingTasksByTitle(ctx context.Context, title string) ([]task.Task, error)
}

// TaskWriter provides task mutations for MCP tools.
type TaskWriter interface {
	UpsertByNotionPageID(ctx context.Context, p task.UpsertByNotionParams) (*task.Task, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status task.Status) (*task.Task, error)
	UpdateMyDay(ctx context.Context, id uuid.UUID, myDay bool) error
	ClearAllMyDay(ctx context.Context) (int64, error)
	Update(ctx context.Context, p task.UpdateParams) (*task.Task, error)
}

// NotionTaskWriter creates and updates tasks in Notion.
type NotionTaskWriter interface {
	UpdatePageStatus(ctx context.Context, pageID, status string) error
	CreateTask(ctx context.Context, p NotionCreateTaskParams) (string, error)
}

// NotionCreateTaskParams holds parameters for creating a task in Notion.
type NotionCreateTaskParams struct {
	DatabaseID  string
	Title       string
	DueDate     string
	Description string
}

// TaskDBIDResolver resolves the Notion database ID for tasks on demand.
type TaskDBIDResolver interface {
	DatabaseIDByRole(ctx context.Context, role string) (string, error)
}

// ContentReader provides content search and retrieval for MCP tools.
type ContentReader interface {
	Search(ctx context.Context, query string, page, perPage int) ([]content.Content, int, error)
	ContentBySlug(ctx context.Context, slug string) (*content.Content, error)
	RecentByType(ctx context.Context, contentType content.Type, since time.Time, limit int) ([]content.Content, error)
}

// ContentWriter creates content records via MCP tools.
type ContentWriter interface {
	CreateContent(ctx context.Context, p content.CreateParams) (*content.Content, error)
}

// GoalReader provides goal queries for MCP tools.
type GoalReader interface {
	Goals(ctx context.Context) ([]goal.Goal, error)
	GoalByTitle(ctx context.Context, title string) (*goal.Goal, error)
}

// GoalWriter provides goal mutations for MCP tools.
type GoalWriter interface {
	UpdateStatus(ctx context.Context, id uuid.UUID, status goal.Status) (*goal.Goal, error)
}

// ProjectWriter provides project mutations for MCP tools.
type ProjectWriter interface {
	UpdateStatus(ctx context.Context, id uuid.UUID, status project.Status, description *string) (*project.Project, error)
}

// CollectedLatestReader provides latest collected data without mandatory time bounds.
type CollectedLatestReader interface {
	LatestCollectedData(ctx context.Context, since *time.Time, maxResults int32) ([]collected.CollectedData, error)
}

// ContentSearcher extends ContentReader with OR-fallback search.
type ContentSearcher interface {
	SearchOR(ctx context.Context, query string, page, perPage int) ([]content.Content, int, error)
}

// SessionNoteReader provides session note queries for MCP tools.
type SessionNoteReader interface {
	NotesByDate(ctx context.Context, startDate, endDate time.Time, noteType *string) ([]session.Note, error)
	LatestNoteByType(ctx context.Context, noteType string) (*session.Note, error)
	MetricsHistory(ctx context.Context, sinceDate time.Time) ([]session.Note, error)
}

// SessionNoteWriter provides session note mutations for MCP tools.
type SessionNoteWriter interface {
	CreateNote(ctx context.Context, p session.CreateParams) (*session.Note, error)
}

// searchResultEntry is a note with a combined RRF score for merged search results.
type searchResultEntry struct {
	Note  note.Note
	Score float64
}

// rrfMerge combines text search results and filter results using Reciprocal Rank Fusion.
// k is the RRF constant (typically 60). Returns merged results sorted by combined score.
func rrfMerge(textResults []note.SearchResult, filterResults []note.Note, limit int) []searchResultEntry {
	const k = 60.0
	scores := make(map[int64]float64)
	notes := make(map[int64]note.Note)

	for rank, r := range textResults {
		scores[r.ID] += 1.0 / (k + float64(rank))
		notes[r.ID] = r.Note
	}
	for rank, n := range filterResults {
		scores[n.ID] += 1.0 / (k + float64(rank))
		if _, ok := notes[n.ID]; !ok {
			notes[n.ID] = n
		}
	}

	// Collect and sort by score descending.
	entries := make([]searchResultEntry, 0, len(scores))
	for id, score := range scores {
		entries = append(entries, searchResultEntry{Note: notes[id], Score: score})
	}
	slices.SortFunc(entries, func(a, b searchResultEntry) int {
		return cmp.Compare(b.Score, a.Score) // descending
	})

	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries
}
