package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- system_status ---

type SystemStatusInput struct {
	Scope *string `json:"scope,omitempty" jsonschema_description:"Scope: summary (default), pipelines, flows"`
}

type SystemStatusOutput struct {
	Scope   string `json:"scope"`
	Message string `json:"message"`
}

func (s *Server) systemStatus(_ context.Context, _ *sdkmcp.CallToolRequest, input SystemStatusInput) (*sdkmcp.CallToolResult, SystemStatusOutput, error) {
	scope := "summary"
	if input.Scope != nil && *input.Scope != "" {
		scope = *input.Scope
	}

	// TODO: Wire stats.Store for flow_runs and feed health queries.
	// Phase 4 consolidation — v1 system_status + collection_stats merged.
	return nil, SystemStatusOutput{
		Scope:   scope,
		Message: fmt.Sprintf("system_status(%s): stats store not yet wired in Phase 4", scope),
	}, nil
}
