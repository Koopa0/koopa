// Package mcp provides an MCP (Model Context Protocol) server exposing
// tools for querying and managing the koopa0.dev knowledge engine.
package mcp

import (
	"context"
	"time"

	"github.com/google/uuid"

	pgvector "github.com/pgvector/pgvector-go"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/stats"
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
	CompletionsByProjectSince(ctx context.Context, since time.Time) ([]activity.ProjectCompletion, error)
}

// ProjectReader provides project lookup for MCP tools.
type ProjectReader interface {
	ProjectBySlug(ctx context.Context, slug string) (*project.Project, error)
	ProjectByAlias(ctx context.Context, alias string) (*project.Project, error)
	ProjectByTitle(ctx context.Context, title string) (*project.Project, error)
	ActiveProjects(ctx context.Context) ([]project.Project, error)
}

// StatsReader provides platform statistics for MCP tools.
type StatsReader interface {
	Drift(ctx context.Context, days int) (*stats.DriftReport, error)
	Learning(ctx context.Context) (*stats.LearningDashboard, error)
}

// NotionTaskWriter creates and updates tasks in Notion.
type NotionTaskWriter interface {
	UpdatePageStatus(ctx context.Context, pageID, status string) error
	UpdatePageProperties(ctx context.Context, pageID string, properties map[string]any) error
	CreateTask(ctx context.Context, p *NotionCreateTaskParams) (string, error)
}

// NotionCreateTaskParams holds parameters for creating a task in Notion.
type NotionCreateTaskParams struct {
	DatabaseID  string
	Title       string
	DueDate     string
	Description string
	Priority    string
	Energy      string
	MyDay       bool
	ProjectID   string // Notion page ID for Project relation
}

// TaskDBIDResolver resolves the Notion database ID for tasks on demand.
type TaskDBIDResolver interface {
	DatabaseIDByRole(ctx context.Context, role string) (string, error)
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
	UpdateStatus(ctx context.Context, id uuid.UUID, status project.Status, description, expectedCadence *string) (*project.Project, error)
}

// SystemStatusReader provides system observability queries for the get_system_status tool.
type SystemStatusReader interface {
	FlowRunsSince(ctx context.Context, since time.Time, flowName, status *string) (*stats.FlowStatusSummary, error)
	FeedHealth(ctx context.Context) (*stats.FeedHealthSummary, error)
	RecentFlowRuns(ctx context.Context, since time.Time, flowName, status *string, limit int) ([]stats.RecentFlowRun, error)
	PipelineSummaries(ctx context.Context, since time.Time) ([]stats.PipelineSummary, error)
}

// PipelineTrigger triggers background pipelines from MCP tools.
type PipelineTrigger interface {
	TriggerCollect(ctx context.Context)
	TriggerNotionSync(ctx context.Context)
}

// searchResultEntry is a thin alias for note.MergedResult used by MCP tool handlers
// to avoid rewriting all response mapping code. The RRF logic lives in note.RRFMerge.
type searchResultEntry = note.MergedResult
