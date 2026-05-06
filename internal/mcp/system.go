package mcp

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/stats"
)

// --- system_status ---

type SystemStatusInput struct {
	Scope *string `json:"scope,omitempty" jsonschema_description:"Scope: summary (default)"`
}

type SystemStatusOutput struct {
	Scope  string                      `json:"scope"`
	Health *stats.SystemHealthSnapshot `json:"health,omitempty"`
}

func (s *Server) systemStatus(ctx context.Context, _ *mcp.CallToolRequest, input SystemStatusInput) (*mcp.CallToolResult, SystemStatusOutput, error) {
	scope := "summary"
	if input.Scope != nil && *input.Scope != "" {
		scope = *input.Scope
	}

	if s.stats == nil {
		return nil, SystemStatusOutput{Scope: scope}, fmt.Errorf("stats store not configured")
	}

	health, err := s.stats.SystemHealth(ctx)
	if err != nil {
		return nil, SystemStatusOutput{Scope: scope}, fmt.Errorf("querying system health: %w", err)
	}

	return nil, SystemStatusOutput{
		Scope:  scope,
		Health: health,
	}, nil
}
