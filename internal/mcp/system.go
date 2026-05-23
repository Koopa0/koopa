package mcp

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/build"
	"github.com/Koopa0/koopa/internal/stats"
)

// --- system_status ---

type SystemStatusInput struct {
	Scope *string `json:"scope,omitempty" jsonschema_description:"Scope: summary (default)"`
}

// SystemStatusOutput is the system_status response. Build identifies the
// running binary so audit callers can confirm which commit produced the
// response; values are injected via -ldflags at link time and default to
// "dev" / "unknown" / "v0.0.0-dev" when running an unstamped local build.
type SystemStatusOutput struct {
	Scope  string                      `json:"scope"`
	Build  build.Info                  `json:"build"`
	Health *stats.SystemHealthSnapshot `json:"health,omitempty"`
}

func (s *Server) systemStatus(ctx context.Context, _ *mcp.CallToolRequest, input SystemStatusInput) (*mcp.CallToolResult, SystemStatusOutput, error) {
	scope := "summary"
	if input.Scope != nil && *input.Scope != "" {
		scope = *input.Scope
	}

	out := SystemStatusOutput{Scope: scope, Build: build.Current()}

	if s.stats == nil {
		return nil, out, fmt.Errorf("stats store not configured")
	}

	health, err := s.stats.SystemHealth(ctx)
	if err != nil {
		return nil, out, fmt.Errorf("querying system health: %w", err)
	}

	out.Health = health
	return nil, out, nil
}
