// Package mcp provides an MCP (Model Context Protocol) server exposing
// tools for querying and managing the koopa0.dev knowledge engine.
package mcp

import (
	"context"

	pgvector "github.com/pgvector/pgvector-go"

	"github.com/koopa0/blog-backend/internal/note"
)

// QueryEmbedder generates an embedding vector for a search query string.
// Interface kept: implementation lives in cmd/mcp (geminiQueryEmbedder), not importable.
type QueryEmbedder interface {
	EmbedQuery(ctx context.Context, text string) (pgvector.Vector, error)
}

// NotionTaskWriter creates and updates tasks in Notion.
// Interface kept: implementation lives in cmd/mcp (notionAdapter), bridging
// notion.Client with MCP-specific NotionCreateTaskParams.
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

// PipelineTrigger triggers background pipelines from MCP tools.
// Interface kept: implementation lives in cmd/mcp (httpPipelineTrigger), not importable.
type PipelineTrigger interface {
	TriggerCollect(ctx context.Context)
	TriggerNotionSync(ctx context.Context)
}

// searchResultEntry is a thin alias for note.MergedResult used by MCP tool handlers
// to avoid rewriting all response mapping code. The RRF logic lives in note.RRFMerge.
type searchResultEntry = note.MergedResult
