package agent

import (
	"context"
	"errors"
	"fmt"
)

// Sentinel errors returned by Authorize.
var (
	// ErrUnknownAgent means the caller name is not present in the registry.
	ErrUnknownAgent = errors.New("agent: unknown agent")
	// ErrForbidden means the caller is known but lacks the requested capability,
	// or is retired.
	ErrForbidden = errors.New("agent: capability denied")
)

// Action identifies a mutation on the coordination store that requires
// capability enforcement. New actions get a new constant — there is no
// string-typed dispatch.
type Action string

const (
	// ActionSubmitTask authorizes task.Store.Submit.
	ActionSubmitTask Action = "submit_task"
	// ActionAcceptTask authorizes task.Store.Accept.
	ActionAcceptTask Action = "accept_task"
	// ActionCompleteTask authorizes task.Store.Complete (delivering a response
	// message + artifact). Uses PublishArtifacts because completing a task
	// requires attaching the deliverable.
	ActionCompleteTask Action = "complete_task"
	// ActionCancelTask authorizes task.Store.Cancel. Only the source agent may
	// cancel a task, enforced separately from capability by the store.
	ActionCancelTask Action = "cancel_task"
	// ActionPublishArtifact authorizes artifact.Store.Add for attaching a
	// structured deliverable to a task already in progress.
	ActionPublishArtifact Action = "publish_artifact"
)

// Allows reports whether this Capability permits the given action.
func (c Capability) Allows(action Action) bool {
	switch action {
	case ActionSubmitTask, ActionCancelTask:
		return c.SubmitTasks
	case ActionAcceptTask:
		return c.ReceiveTasks
	case ActionCompleteTask, ActionPublishArtifact:
		return c.PublishArtifacts
	}
	return false
}

// Authorized is a compile-time proof that agent.Authorize was called and
// approved a specific (caller, action) pair.
//
// All fields are unexported, so external packages cannot literal-construct
// this value. The only construction path is Authorize() below. task.Store
// and artifact.Store mutation methods accept Authorized as a parameter;
// therefore a handler that bypasses the capability check cannot compile.
//
// See docs/architecture/coordination-layer-target.md §10 for the threat
// model this type is defending against.
type Authorized struct {
	caller Name
	action Action
}

// Caller returns the agent name that was authorized.
func (a Authorized) Caller() Name { return a.caller }

// Action returns the action that was authorized.
func (a Authorized) Action() Action { return a.action }

// Authorize checks whether the named caller may perform the given action.
// On success, the returned Authorized value can be passed to coordination
// store mutation methods. On failure, the error wraps ErrUnknownAgent or
// ErrForbidden so handlers can use errors.Is for classification.
//
// ctx is unused today but reserved so future policy layers (per-request
// quotas, auditing) can plug in without changing the call sites.
func Authorize(_ context.Context, r *Registry, caller Name, action Action) (Authorized, error) {
	a, ok := r.Lookup(caller)
	if !ok {
		return Authorized{}, fmt.Errorf("%w: %s", ErrUnknownAgent, caller)
	}
	if a.Status == StatusRetired {
		return Authorized{}, fmt.Errorf("%w: %s is retired", ErrForbidden, caller)
	}
	if !a.Capability.Allows(action) {
		return Authorized{}, fmt.Errorf("%w: %s cannot %s", ErrForbidden, caller, action)
	}
	return Authorized{caller: caller, action: action}, nil
}
