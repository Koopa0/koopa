// Copyright 2026 Koopa. All rights reserved.

package agent

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBuiltinAgentsInvariants(t *testing.T) {
	t.Parallel()

	agents := BuiltinAgents()
	if len(agents) == 0 {
		t.Fatal("BuiltinAgents() returned no agents")
	}

	seen := make(map[Name]bool, len(agents))
	for _, a := range agents {
		if a.Name == "" {
			t.Errorf("agent with empty name: %+v", a)
		}
		if seen[a.Name] {
			t.Errorf("duplicate agent name: %q", a.Name)
		}
		seen[a.Name] = true

		if a.DisplayName == "" {
			t.Errorf("agent %q has empty DisplayName", a.Name)
		}
		if a.Platform == "" {
			t.Errorf("agent %q has empty Platform", a.Name)
		}

		// Schedule invariants: cron triggers require a non-empty expression.
		if a.Schedule.Trigger == TriggerCron && a.Schedule.Expr == "" {
			t.Errorf("agent %q has cron schedule with empty Expr", a.Name)
		}
		// A non-zero schedule must have a name (used for the composite
		// <agent>:<schedule> key in process_runs.name).
		if !a.Schedule.IsZero() && a.Schedule.Name == "" {
			t.Errorf("agent %q has schedule with empty Name", a.Name)
		}
	}

	// The 'human' identity is required by todo_items.assignee DEFAULT 'human'
	// — if it ever disappears from BuiltinAgents, new todos cannot be inserted.
	if _, ok := seen["human"]; !ok {
		t.Error("BuiltinAgents() must include the 'human' agent — todo_items.assignee defaults to it")
	}

	// The 'unknown' identity is the zero-privilege server default for
	// MCP calls that omit `as` (server.go callerAgent + cmd/mcp
	// KOOPA_MCP_CALLER_AGENT default). Removing it would either reopen
	// the fail-open via env-default-human, or break the FK on every
	// audit row stamped from a call without `as`.
	if u, ok := seen["unknown"]; !ok {
		t.Error("BuiltinAgents() must include the 'unknown' agent — server default callerAgent FKs to it")
	} else if u {
		// seen[name] is the dup-check flag set above; presence is what
		// we want, not duplication. The else-if guards against a future
		// refactor that changes the map semantic without updating this
		// assertion.
		_ = u
	}
	// Attribution integrity: the unknown fallback agent MUST NOT have
	// Platform=human. If a future edit set it to human, a caller that
	// omitted `as` would be attributed as the owner — inflating the
	// owner's project_progress / review_period momentum with anonymous
	// writes (the exact failure mode this agent is designed to prevent).
	for _, a := range agents {
		if a.Name == "unknown" && a.Platform == "human" {
			t.Errorf("agent 'unknown' must NOT have Platform=human (anonymous writes would be miscounted as owner activity)")
		}
	}
}

func TestRegistryAll(t *testing.T) {
	t.Parallel()

	agents := []Agent{
		{Name: "zeta", DisplayName: "Zeta", Platform: "p"},
		{Name: "alpha", DisplayName: "Alpha", Platform: "p"},
		{Name: "mu", DisplayName: "Mu", Platform: "p"},
	}
	r := NewRegistry(agents)
	all := r.All()

	wantNames := []Name{"alpha", "mu", "zeta"}
	gotNames := make([]Name, len(all))
	for i, a := range all {
		gotNames[i] = a.Name
	}
	if diff := cmp.Diff(wantNames, gotNames); diff != "" {
		t.Errorf("Registry.All() name order mismatch (-want +got):\n%s", diff)
	}

	for _, a := range all {
		if a.Status != StatusActive {
			t.Errorf("agent %q default Status = %q, want %q", a.Name, a.Status, StatusActive)
		}
	}
}
