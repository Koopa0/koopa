// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/Koopa0/koopa/internal/todo"
)

// --- triage_todo validation ---

// TestTriageTodo_Validation drives every handler-level rejection through the
// real handler on a store-less server: each case must fail BEFORE any
// mutation (a validation gap would dereference the nil pool instead of
// returning the expected error).
func TestTriageTodo_Validation(t *testing.T) {
	s := newTestServer()
	const validID = "550e8400-e29b-41d4-a716-446655440000"
	tests := []struct {
		name    string
		input   TriageTodoInput
		wantErr string
	}{
		{name: "invalid verdict", input: TriageTodoInput{ID: validID, Verdict: "approve"}, wantErr: "invalid verdict"},
		{name: "empty verdict", input: TriageTodoInput{ID: validID}, wantErr: "invalid verdict"},
		{name: "project rejected for someday", input: TriageTodoInput{ID: validID, Verdict: "someday", Project: "koopa"}, wantErr: "only with verdict accept"},
		{name: "due rejected for dismiss", input: TriageTodoInput{ID: validID, Verdict: "dismiss", Due: new("2026-08-01")}, wantErr: "only with verdict accept"},
		{name: "energy rejected for restore", input: TriageTodoInput{ID: validID, Verdict: "restore", Energy: new("high")}, wantErr: "only with verdict accept"},
		{name: "invalid id", input: TriageTodoInput{ID: "not-a-uuid", Verdict: "accept"}, wantErr: "invalid id"},
		{name: "invalid energy", input: TriageTodoInput{ID: validID, Verdict: "accept", Energy: new("extreme")}, wantErr: "energy must be one of"},
		{name: "invalid due format", input: TriageTodoInput{ID: validID, Verdict: "accept", Due: new("01/08/2026")}, wantErr: "invalid due date"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.triageTodo, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestValidateTriageInput_VerdictMapping pins the closed verdict → transition
// mapping locked by the PR-5 contract: accept inbox→todo, someday
// inbox→someday, dismiss inbox→dismissed, restore dismissed|someday→inbox.
// The expected values are hand-written from the contract, so a miswired
// target or source set fails here without a database.
func TestValidateTriageInput_VerdictMapping(t *testing.T) {
	const validID = "550e8400-e29b-41d4-a716-446655440000"
	tests := []struct {
		name        string
		verdict     string
		wantTarget  todo.State
		wantSources []todo.State
	}{
		{name: "accept", verdict: "accept", wantTarget: todo.StateTodo, wantSources: []todo.State{todo.StateInbox}},
		{name: "someday", verdict: "someday", wantTarget: todo.StateSomeday, wantSources: []todo.State{todo.StateInbox}},
		{name: "dismiss", verdict: "dismiss", wantTarget: todo.StateDismissed, wantSources: []todo.State{todo.StateInbox}},
		{name: "restore", verdict: "restore", wantTarget: todo.StateInbox, wantSources: []todo.State{todo.StateDismissed, todo.StateSomeday}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := validateTriageInput(&TriageTodoInput{ID: validID, Verdict: tt.verdict})
			if err != nil {
				t.Fatalf("validateTriageInput(%q) error = %v, want nil", tt.verdict, err)
			}
			if plan.rule.target != tt.wantTarget {
				t.Errorf("target = %q, want %q", plan.rule.target, tt.wantTarget)
			}
			if diff := cmp.Diff(tt.wantSources, plan.rule.sources); diff != "" {
				t.Errorf("sources mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestValidateTriageInput_AcceptFields proves each member of the closed
// energy set passes and the due date parses into the exact calendar day —
// accept's optional fields survive validation intact.
func TestValidateTriageInput_AcceptFields(t *testing.T) {
	const validID = "550e8400-e29b-41d4-a716-446655440000"
	for _, energy := range []string{"high", "medium", "low"} {
		t.Run("energy "+energy, func(t *testing.T) {
			plan, err := validateTriageInput(&TriageTodoInput{
				ID:      validID,
				Verdict: "accept",
				Energy:  new(energy),
				Due:     new("2026-08-01"),
			})
			if err != nil {
				t.Fatalf("validateTriageInput(accept, energy=%q) error = %v, want nil", energy, err)
			}
			if plan.energy == nil || *plan.energy != energy {
				t.Errorf("plan.energy = %v, want %q", plan.energy, energy)
			}
			wantDue := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
			if plan.due == nil || !plan.due.Equal(wantDue) {
				t.Errorf("plan.due = %v, want %v", plan.due, wantDue)
			}
		})
	}
}

// --- list_inbox age computation ---

// TestAgeDays pins age_days as whole elapsed 24-hour periods, floored —
// hand-computed expectations, no wall clock involved.
func TestAgeDays(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		createdAt time.Time
		want      int
	}{
		{name: "captured an hour ago", createdAt: now.Add(-time.Hour), want: 0},
		{name: "just under one day", createdAt: now.Add(-23 * time.Hour), want: 0},
		{name: "one day and one hour", createdAt: now.Add(-25 * time.Hour), want: 1},
		{name: "exactly three days", createdAt: now.Add(-72 * time.Hour), want: 3},
		{name: "six days twenty-three hours", createdAt: now.Add(-167 * time.Hour), want: 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ageDays(tt.createdAt, now); got != tt.want {
				t.Errorf("ageDays(%v, %v) = %d, want %d", tt.createdAt, now, got, tt.want)
			}
		})
	}
}
