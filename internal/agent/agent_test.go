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

	// No synthetic fallback agents. 'system' is gone — current_actor() RAISEs
	// when koopa.actor is unset instead of attributing to a fake agent. 'unknown'
	// is gone — an MCP call without `as` is refused at withActorTx (empty caller
	// identity). Re-introducing either would reopen silent or anonymous
	// attribution, the exact failure modes the no-fallback design prevents.
	for _, banned := range []Name{"system", "unknown"} {
		if seen[banned] {
			t.Errorf("BuiltinAgents() must NOT include the %q fallback agent — every audited write declares a real actor", banned)
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
