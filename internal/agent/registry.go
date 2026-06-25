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
			Name:        "codex",
			DisplayName: "Codex",
			Platform:    "codex",
			Description: "Dev collaborator (Codex CLI) — repo work and cross-review sessions",
		},
		{
			Name:        "hermes",
			DisplayName: "Hermes",
			Platform:    "hermes",
			Description: "Scheduled assistant — curates the personal Obsidian vault on assigned cron jobs",
		},
		{
			Name:        "claude",
			DisplayName: "Claude",
			Platform:    "claude-code",
			Description: "General Claude session — search and agent-surface work",
		},
		{
			Name:        "human",
			DisplayName: "Koopa",
			Platform:    "human",
			Description: "Direct manual operation by the user",
		},
		// No synthetic agents. There is no 'system': when koopa.actor is
		// unset the audit trigger attributes to 'human' (the owner is the
		// only one doing direct/manual DB ops in a single-user system). There
		// is no 'unknown': an MCP call without `as` is refused at withActorTx
		// (empty caller identity). Every agent here is a real, named caller.
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
