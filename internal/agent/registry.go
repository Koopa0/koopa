package agent

import (
	"fmt"
	"sync"
)

// BuiltinAgents returns the authoritative agent roster. Edit this literal to
// add, remove, or modify an agent — the startup sync reconciles the DB on
// next restart.
//
// Capability and schedule flags live on agent.Agent in the Go registry, NOT
// in the DB — authorization is enforced via agent.Authorized (compile-time
// wrapper in authorize.go).
func BuiltinAgents() []Agent {
	return []Agent{
		{
			Name:        "hq",
			DisplayName: "Studio HQ",
			Platform:    "claude-cowork",
			Description: "CEO — decisions, delegation, morning briefing",
			Capability: Capability{
				SubmitTasks:      true,
				ReceiveTasks:     false,
				PublishArtifacts: true,
			},
			Schedule: Schedule{
				Name:    "morning-briefing",
				Trigger: TriggerCron,
				Expr:    "0 8 * * *",
				Backend: "cowork_desktop",
				Purpose: "Daily briefing — todos, projects, goals, hypotheses, RSS highlights",
			},
		},
		{
			Name:        "content-studio",
			DisplayName: "Content Studio",
			Platform:    "claude-cowork",
			Description: "Content strategy, writing, publishing",
			Capability: Capability{
				SubmitTasks:      true,
				ReceiveTasks:     true,
				PublishArtifacts: true,
			},
			Schedule: Schedule{
				Name:    "pipeline-check",
				Trigger: TriggerCron,
				Expr:    "0 14 * * *",
				Backend: "cowork_desktop",
				Purpose: "Daily content pipeline health + RSS monitoring",
			},
		},
		{
			Name:        "research-lab",
			DisplayName: "Research Lab",
			Platform:    "claude-cowork",
			Description: "Deep research, structured reports",
			Capability: Capability{
				SubmitTasks:      true,
				ReceiveTasks:     true,
				PublishArtifacts: true,
			},
			Schedule: Schedule{
				Name:    "industry-scan",
				Trigger: TriggerCron,
				Expr:    "0 9 * * 1",
				Backend: "cowork_desktop",
				Purpose: "Weekly industry trend scanning",
			},
		},
		{
			Name:        "learning-studio",
			DisplayName: "Learning Studio",
			Platform:    "claude-cowork",
			Description: "LeetCode coaching, spaced repetition",
			Capability: Capability{
				SubmitTasks:      false,
				ReceiveTasks:     true,
				PublishArtifacts: true,
			},
		},
		{
			Name:        "koopa0-dev",
			DisplayName: "koopa",
			Platform:    "claude-code",
			Description: "koopa development project",
			Capability:  Capability{},
		},
		{
			Name:        "go-spec",
			DisplayName: "go-spec",
			Platform:    "claude-code",
			Description: "Go spec configuration project",
			Capability:  Capability{},
		},
		{
			Name:        "claude",
			DisplayName: "Claude",
			Platform:    "claude-web",
			Description: "General Claude Web session",
			Capability:  Capability{},
		},
		{
			Name:        "human",
			DisplayName: "Koopa",
			Platform:    "human",
			Description: "Direct manual operation by the user",
			Capability: Capability{
				SubmitTasks: true,
			},
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
			Capability:  Capability{},
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
