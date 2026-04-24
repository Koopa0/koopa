package agent

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCapabilityAllows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		capability Capability
		action     Action
		want       bool
	}{
		{
			name:       "submit task requires SubmitTasks",
			capability: Capability{SubmitTasks: true},
			action:     ActionSubmitTask,
			want:       true,
		},
		{
			name:       "cancel task uses SubmitTasks",
			capability: Capability{SubmitTasks: true},
			action:     ActionCancelTask,
			want:       true,
		},
		{
			name:       "accept task requires ReceiveTasks",
			capability: Capability{ReceiveTasks: true},
			action:     ActionAcceptTask,
			want:       true,
		},
		{
			name:       "complete task requires PublishArtifacts",
			capability: Capability{PublishArtifacts: true},
			action:     ActionCompleteTask,
			want:       true,
		},
		{
			name:       "publish artifact requires PublishArtifacts",
			capability: Capability{PublishArtifacts: true},
			action:     ActionPublishArtifact,
			want:       true,
		},
		{
			name:       "empty capability denies submit",
			capability: Capability{},
			action:     ActionSubmitTask,
			want:       false,
		},
		{
			name:       "empty capability denies accept",
			capability: Capability{},
			action:     ActionAcceptTask,
			want:       false,
		},
		{
			name:       "receive does not imply submit",
			capability: Capability{ReceiveTasks: true, PublishArtifacts: true},
			action:     ActionSubmitTask,
			want:       false,
		},
		{
			name:       "submit does not imply accept",
			capability: Capability{SubmitTasks: true, PublishArtifacts: true},
			action:     ActionAcceptTask,
			want:       false,
		},
		{
			name:       "publish artifact is NOT implied by receive",
			capability: Capability{ReceiveTasks: true},
			action:     ActionPublishArtifact,
			want:       false,
		},
		{
			name:       "unknown action denied",
			capability: Capability{SubmitTasks: true, ReceiveTasks: true, PublishArtifacts: true},
			action:     Action("unknown"),
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.capability.Allows(tc.action)
			if got != tc.want {
				t.Errorf("Capability.Allows(%q) = %v, want %v", tc.action, got, tc.want)
			}
		})
	}
}

func TestAuthorize(t *testing.T) {
	t.Parallel()

	registry := NewRegistry([]Agent{
		{
			Name:        "hq",
			DisplayName: "HQ",
			Platform:    "claude-cowork",
			Capability: Capability{
				SubmitTasks:      true,
				PublishArtifacts: true,
			},
		},
		{
			Name:        "research-lab",
			DisplayName: "Research Lab",
			Platform:    "claude-cowork",
			Capability: Capability{
				ReceiveTasks:     true,
				PublishArtifacts: true,
			},
		},
		{
			Name:        "retired-one",
			DisplayName: "Retired One",
			Platform:    "claude-cowork",
			Capability:  Capability{SubmitTasks: true},
		},
	})
	registry.SetStatus("retired-one", StatusRetired)

	ctx := t.Context()

	tests := []struct {
		name    string
		caller  Name
		action  Action
		wantErr error
	}{
		{
			name:   "hq can submit",
			caller: "hq",
			action: ActionSubmitTask,
		},
		{
			name:   "research-lab can accept",
			caller: "research-lab",
			action: ActionAcceptTask,
		},
		{
			name:   "research-lab can complete",
			caller: "research-lab",
			action: ActionCompleteTask,
		},
		{
			name:    "hq cannot accept",
			caller:  "hq",
			action:  ActionAcceptTask,
			wantErr: ErrForbidden,
		},
		{
			name:    "research-lab cannot submit",
			caller:  "research-lab",
			action:  ActionSubmitTask,
			wantErr: ErrForbidden,
		},
		{
			name:    "unknown caller rejected",
			caller:  "ghost",
			action:  ActionSubmitTask,
			wantErr: ErrUnknownAgent,
		},
		{
			name:    "retired agent rejected",
			caller:  "retired-one",
			action:  ActionSubmitTask,
			wantErr: ErrForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			auth, err := Authorize(ctx, registry, tc.caller, tc.action)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Authorize: got err=%v, want wraps %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Authorize: unexpected error: %v", err)
			}
			if auth.Caller() != tc.caller {
				t.Errorf("Authorized.Caller() = %q, want %q", auth.Caller(), tc.caller)
			}
			if auth.Action() != tc.action {
				t.Errorf("Authorized.Action() = %q, want %q", auth.Action(), tc.action)
			}
		})
	}
}

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

func TestAuthorizedZeroValueEmpty(t *testing.T) {
	t.Parallel()

	// The zero value of Authorized must not authorize anything — external
	// packages constructing Authorized{} should not pass for any real caller
	// check. This is a belt-and-suspenders verification: the unexported
	// fields already prevent external literal construction, but we want to
	// make sure the zero value also returns empty accessors so a store
	// receiving it would at least log the emptiness rather than act on
	// stale data.
	var zero Authorized
	if zero.Caller() != "" {
		t.Errorf("zero Authorized.Caller() = %q, want empty", zero.Caller())
	}
	if zero.Action() != "" {
		t.Errorf("zero Authorized.Action() = %q, want empty", zero.Action())
	}
}
