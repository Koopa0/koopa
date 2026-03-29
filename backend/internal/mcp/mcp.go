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

// PipelineTrigger triggers background pipelines from MCP tools.
// Interface kept: implementation lives in cmd/mcp (httpPipelineTrigger), not importable.
type PipelineTrigger interface {
	TriggerCollect(ctx context.Context)
	TriggerNotionSync(ctx context.Context)
}

// searchResultEntry is a thin alias for note.MergedResult used by MCP tool handlers
// to avoid rewriting all response mapping code. The RRF logic lives in note.RRFMerge.
type searchResultEntry = note.MergedResult
