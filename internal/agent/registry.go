// Copyright 2026 Koopa. All rights reserved.

package agent

import (
	"fmt"
	"sync"
)

// BuiltinAgents returns the authoritative agent roster. Edit this literal to
// add, remove, or modify an agent — the startup sync reconciles the DB on
// next restart.
//
// Schedule definitions live on agent.Agent in the Go registry, not in the
// DB. The agents table is an identity projection only (name, platform,
// status).
func BuiltinAgents() []Agent {
	return []Agent{
		{
			Name:        "planner",
			DisplayName: "Planner",
			Platform:    "claude-cowork",
			Description: "Daily planner — morning briefing and candidate day plan, in conversation with Koopa",
			Schedule: Schedule{
				Name:    "morning-briefing",
				Trigger: TriggerCron,
				Expr:    "0 8 * * *",
				Backend: "cowork_desktop",
				Purpose: "Daily briefing — todos, goals, RSS highlights, content pipeline",
			},
		},
		{
			Name:        "koopa0-dev",
			DisplayName: "koopa",
			Platform:    "claude-code",
			Description: "koopa development project",
		},
		{
			Name:        "go-spec",
			DisplayName: "go-spec",
			Platform:    "claude-code",
			Description: "Go spec configuration project",
		},
		{
			Name:        "codex",
			DisplayName: "Codex",
			Platform:    "codex",
			Description: "Dev collaborator (Codex CLI) — repo work and cross-review sessions",
		},
		{
			Name:        "hermes",
			DisplayName: "Hermes",
			Platform:    "claude-code",
			Description: "Scheduled assistant — curates the personal Obsidian vault on assigned cron jobs",
		},
		{
			Name:        "claude",
			DisplayName: "Claude",
			Platform:    "claude-web",
			Description: "General Claude Web session",
		},
		{
			Name:        "human",
			DisplayName: "Koopa",
			Platform:    "human",
			Description: "Direct manual operation by the user",
		},
		{
			// The audit trigger current_actor() falls back to the literal
			// 'system' when koopa.actor is unset. Registering it here
			// ensures activity_events.actor FK resolves even when the Go
			// tx wrapper is bypassed (pg_cron, manual psql ops, or a
			// regression where SET LOCAL is forgotten). Appearance in
			// activity_events is a red flag — the Go path should always
			// set koopa.actor to a real agent name.
			Name:        "system",
			DisplayName: "System",
			Platform:    "system",
			Description: "Database-level writes without Go caller context — pg_cron jobs, manual ops, or fallback when koopa.actor is unset",
		},
		{
			// Attribution fallback for MCP calls that omit the `as`
			// field. Lives at the SERVER default (server.go callerAgent
			// + cmd/mcp KOOPA_MCP_CALLER_AGENT default). There is no
			// tool-layer authz (Option B), so this does not gate access;
			// it controls ATTRIBUTION — a call with no identity writes as
			// "unknown", which project_progress / review_period do NOT
			// count as owner (human) activity. Do NOT default this to
			// "human": that would stamp anonymous writes as Koopa's own.
			// Distinct from "system": "system" attributes DB-level writes
			// that bypass the Go actor middleware; "unknown" attributes
			// MCP calls whose middleware ran but received no identity.
			// Surfacing "unknown" as actor in activity_events is a
			// client-side red flag — the cowork project instruction must
			// include `as: "<agent_name>"` on every tool call.
			Name:        "unknown",
			DisplayName: "Unknown caller",
			Platform:    "system",
			Description: "Zero-privilege fallback for MCP calls without an `as` field. Real agents MUST self-identify per project instructions — surfacing 'unknown' as actor signals a client that forgot to pass `as`.",
		},
	}
}

// Registry is an in-memory lookup map built from BuiltinAgents. It is safe
// for concurrent read use; SetStatus must be called only during startup
// (before HTTP serving begins) because it takes a write lock without any
// consistency guarantee for in-flight lookups.
type Registry struct {
	mu     sync.RWMutex
	byName map[Name]Agent
}

// NewRegistry builds a Registry from a slice of Agent literals. All agents
// start with Status==StatusActive; SyncToTable updates individual rows if
// the DB reports a different status.
func NewRegistry(agents []Agent) *Registry {
	byName := make(map[Name]Agent, len(agents))
	for i := range agents {
		a := agents[i]
		if a.Status == "" {
			a.Status = StatusActive
		}
		byName[a.Name] = a
	}
	return &Registry{byName: byName}
}

// NewBuiltinRegistry is a convenience for wiring in cmd/app/main.go — it
// calls NewRegistry(BuiltinAgents()).
func NewBuiltinRegistry() *Registry {
	return NewRegistry(BuiltinAgents())
}

// Lookup returns the Agent with the given name and reports whether it was
// found. The returned Agent is a value copy; mutating it does not affect
// the registry.
func (r *Registry) Lookup(name Name) (Agent, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byName[name]
	return a, ok
}

// Get returns the Agent by name or an error if the name is unknown. Useful
// at call sites that want to early-return on registry misses.
func (r *Registry) Get(name Name) (Agent, error) {
	a, ok := r.Lookup(name)
	if !ok {
		return Agent{}, fmt.Errorf("%w: %s", ErrUnknownAgent, name)
	}
	return a, nil
}

// All returns a copy of every Agent in the registry in deterministic order
// (sorted by Name).
func (r *Registry) All() []Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Agent, 0, len(r.byName))
	for name := range r.byName {
		out = append(out, r.byName[name])
	}
	sortAgentsByName(out)
	return out
}

// SetStatus updates the cached Status for an agent. Called by SyncToTable
// after reconciling against the DB projection. Safe to call during startup
// only — after HTTP serving begins, status transitions are one-way
// (active → retired) and should not happen in a running process.
func (r *Registry) SetStatus(name Name, s Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.byName[name]; ok {
		a.Status = s
		r.byName[name] = a
	}
}

func sortAgentsByName(agents []Agent) {
	// Small N — insertion sort avoids pulling in sort.Slice just for this.
	for i := 1; i < len(agents); i++ {
		for j := i; j > 0 && agents[j-1].Name > agents[j].Name; j-- {
			agents[j-1], agents[j] = agents[j], agents[j-1]
		}
	}
}
