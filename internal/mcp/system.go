// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
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
//
// LastAgentScheduleRuns reports the most recent observed start time for
// every built-in agent that declares a Schedule. A nil value means the
// agent has never been observed running an agent_schedule entry — the key
// is still present so consumers can distinguish "missing data" from
// "agent absent from the registry". Unknown agents that appear only in
// process_runs (registry drift) are included as well so the field is an
// honest view of the audit trail.
type SystemStatusOutput struct {
	Scope                 string                      `json:"scope"`
	Build                 build.Info                  `json:"build"`
	Health                *stats.SystemHealthSnapshot `json:"health,omitempty"`
	LastAgentScheduleRuns map[string]*string          `json:"last_agent_schedule_runs"`
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

	observed, err := s.stats.LastAgentScheduleRuns(ctx)
	if err != nil {
		return nil, out, fmt.Errorf("querying agent schedule runs: %w", err)
	}
	out.LastAgentScheduleRuns = mergeAgentScheduleRuns(scheduledAgents(s.registry), observed)

	return nil, out, nil
}

// scheduledAgents returns the names of registry agents that declare a
// non-empty Schedule. These are the agents the external runner is expected
// to fire; agents without a Schedule are deliberately excluded because they
// have no scheduled cadence to observe.
func scheduledAgents(r *agent.Registry) []agent.Name {
	if r == nil {
		return nil
	}
	all := r.All()
	out := make([]agent.Name, 0, len(all))
	for i := range all {
		if !all[i].Schedule.IsZero() {
			out = append(out, all[i].Name)
		}
	}
	return out
}

// mergeAgentScheduleRuns produces the wire map for LastAgentScheduleRuns:
// every expected agent appears with a nil value (representing "never
// observed"), then DB-observed runs overlay their formatted timestamps.
// Observed agents not present in expected are included as well so
// registry/audit drift remains visible rather than silently hidden.
func mergeAgentScheduleRuns(expected []agent.Name, observed map[string]time.Time) map[string]*string {
	out := make(map[string]*string, len(expected)+len(observed))
	for _, n := range expected {
		out[string(n)] = nil
	}
	for name, t := range observed {
		ts := t.UTC().Format(time.RFC3339)
		out[name] = &ts
	}
	return out
}
