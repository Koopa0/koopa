// authorize.go defines the compile-time capability gate.
//
// The central type is Authorized — a value that proves Authorize() was
// called and approved a specific (caller, action) pair. Every mutation
// method on internal/agent/task.Store and internal/agent/artifact.Store
// accepts Authorized as a parameter. Because its fields are unexported,
// NO external package can literal-construct it; the only way to obtain
// one is Authorize(), and the only way to call a mutation is to supply
// one. A handler that bypasses the capability check fails to compile,
// not at runtime.
//
// Adding a new Action: (1) add the constant below, (2) extend
// Capability.Allows so it maps to the right capability bit. The mutation
// method that consumes the new Action then uses mustHaveAction(auth,
// ActionFoo) to verify the incoming Authorized matches — belt-and-braces
// against an Authorized produced for a different action being reused.

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
	// ActionRequestRevision authorizes task.Store.RequestRevision. The source
	// agent requests changes on a completed task. Uses SubmitTasks capability.
	ActionRequestRevision Action = "request_revision"
	// ActionReacceptTask authorizes task.Store.Reaccept. The assignee picks up
	// a revision-requested task. Uses ReceiveTasks capability.
	ActionReacceptTask Action = "reaccept_task"
)

// Allows reports whether this Capability permits the given action.
func (c Capability) Allows(action Action) bool {
	switch action {
	case ActionSubmitTask, ActionCancelTask, ActionRequestRevision:
		return c.SubmitTasks
	case ActionAcceptTask, ActionReacceptTask:
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
