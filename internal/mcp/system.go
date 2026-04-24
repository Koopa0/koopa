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
	Scope    string          `json:"scope"`
	Overview *stats.Overview `json:"overview,omitempty"`
}

func (s *Server) systemStatus(ctx context.Context, _ *mcp.CallToolRequest, input SystemStatusInput) (*mcp.CallToolResult, SystemStatusOutput, error) {
	scope := "summary"
	if input.Scope != nil && *input.Scope != "" {
		scope = *input.Scope
	}

	if s.stats == nil {
		return nil, SystemStatusOutput{Scope: scope}, fmt.Errorf("stats store not configured")
	}

	overview, err := s.stats.Overview(ctx)
	if err != nil {
		return nil, SystemStatusOutput{}, fmt.Errorf("querying system status: %w", err)
	}

	return nil, SystemStatusOutput{
		Scope:    scope,
		Overview: overview,
	}, nil
}
