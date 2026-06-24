// Copyright 2026 Koopa. All rights reserved.

// Package agent is the single source of truth for the koopa agent
// registry and the startup-time projection into the agents table.
//
// Agents are defined as a Go literal in BuiltinAgents() — there is no
// configuration file, database seed, or admin UI. Modifying the agent roster
// is a code change that goes through the normal review + rebuild cycle.
package agent

import (
	"errors"
)

// ErrUnknownAgent means the caller name is not present in the registry or
// the agents table.
var ErrUnknownAgent = errors.New("agent: unknown agent")

// Name is the unique identifier for an agent. Matches the Go literal in
// BuiltinAgents() and the primary key in the agents table.
type Name string

// Status mirrors the agents.status SQL enum.
type Status string

const (
	StatusActive  Status = "active"
	StatusRetired Status = "retired"
)

// TriggerKind identifies how an agent's schedule fires.
type TriggerKind string

const (
	// TriggerNone means the agent has no schedule (interactive only).
	TriggerNone TriggerKind = ""
	// TriggerCron uses a standard cron expression.
	TriggerCron TriggerKind = "cron"
	// TriggerManual fires only when explicitly invoked.
	TriggerManual TriggerKind = "manual"
)

// Schedule describes an agent's standing instruction to run on a recurring
// basis. The zero value (TriggerNone) means no schedule. Schedule definitions
// live on the Agent struct itself — there is no separate schedules table.
type Schedule struct {
	// Name is the human-readable label for the schedule (e.g. "morning-briefing").
	// Combined with the agent Name to form the composite key written to
	// process_runs.name ("<agent>:<schedule>") when kind='agent_schedule'.
	Name string
	// Trigger is the firing strategy.
	Trigger TriggerKind
	// Expr is a cron expression when Trigger==TriggerCron. Empty for other kinds.
	Expr string
	// Backend names the runtime that executes the schedule (cowork_desktop,
	// claude_code, github_actions, koopa_native). Informational — routing is
	// handled by the dispatcher, not by this string.
	Backend string
	// Purpose is a one-line description of what the schedule achieves.
	Purpose string
}

// IsZero reports whether this Schedule is the empty value (no trigger).
func (s Schedule) IsZero() bool {
	return s.Trigger == TriggerNone && s.Name == "" && s.Expr == ""
}

// Agent is the complete in-process description of an agent. It carries its
// own Schedule — there is no separate AgentCard type and no Go-to-A2A
// adapter. If an A2A wire interop scenario materializes, an adapter
// function is added at that point (see target doc §16.4).
type Agent struct {
	Name        Name
	DisplayName string
	Platform    string
	Description string
	Schedule    Schedule
	// Status reflects the most recent DB projection. It is populated by
	// Registry.SetStatus after agent.SyncToTable runs at startup. Lookups via
	// Registry.Lookup return the Agent literal directly with Status==StatusActive,
	// so code paths that only consult the registry see live agents.
	Status Status
}

// RegistryRow is a snapshot of an agent row from the agents table. Returned
// by Store.List during the startup sync reconciliation.
type RegistryRow struct {
	Name        Name
	DisplayName string
	Platform    string
	Description string
	Status      Status
}
