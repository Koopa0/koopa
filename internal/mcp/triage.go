// Copyright 2026 Koopa. All rights reserved.

// triage.go holds the owner triage loop: list_inbox (read) and triage_todo
// (write). Both are cross-creator BY DESIGN — unlike the caller-scoped
// list_todos / resolve_todo readback loop, they operate on the owner's
// triage queue and execute the owner's verdict on any creator's todo, not
// caller self-cleanup. They are owner-present conversation tools: never
// called from scheduled or autonomous runs, and forbidden to Hermes by
// contract. Every triage mutation runs inside withActorTx so its audit
// event is attributed to the calling agent.

package mcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/todo"
)

// --- list_inbox ---

// ListInboxInput is the input for the list_inbox tool. It carries only the
// caller self-identification — the queue it reads is the owner's single
// inbox, so there are no filters and no caller-scoping.
type ListInboxInput struct {
	As string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making the call. list_inbox is cross-creator by design (it reads the owner's triage queue), so this attributes the read but never narrows it."`
}

// InboxTodoItem is one row of list_inbox: an inbox todo awaiting the owner's
// verdict, regardless of which agent captured it.
type InboxTodoItem struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	CreatedBy   string `json:"created_by"`
	AgeDays     int    `json:"age_days"`
	Description string `json:"description"`
}

// ListInboxOutput is the output of the list_inbox tool, oldest capture first.
type ListInboxOutput struct {
	Todos []InboxTodoItem `json:"todos"`
}

func (s *Server) listInbox(ctx context.Context, _ *mcp.CallToolRequest, _ ListInboxInput) (*mcp.CallToolResult, ListInboxOutput, error) {
	rows, err := s.todos.InboxItems(ctx)
	if err != nil {
		return nil, ListInboxOutput{}, fmt.Errorf("listing inbox todos: %w", err)
	}

	now := time.Now()
	items := make([]InboxTodoItem, len(rows))
	for i := range rows {
		items[i] = InboxTodoItem{
			ID:          rows[i].ID.String(),
			Title:       rows[i].Title,
			CreatedBy:   rows[i].CreatedBy,
			AgeDays:     ageDays(rows[i].CreatedAt, now),
			Description: rows[i].Description,
		}
	}
	return nil, ListInboxOutput{Todos: items}, nil
}

// ageDays returns the whole 24-hour periods elapsed from createdAt to now —
// the age_days a triage queue row advertises.
func ageDays(createdAt, now time.Time) int {
	return int(now.Sub(createdAt) / (24 * time.Hour))
}

// --- triage_todo ---

// triageRule pairs a verdict's target state with the closed set of source
// states it may act on.
type triageRule struct {
	target  todo.State
	sources []todo.State
}

// triageVerdicts is the closed verdict allowlist for triage_todo, following
// the resolveTodoStates pattern: this map is the runtime gate — the catalog's
// FieldEnums advertising is advisory schema decoration only. accept, someday,
// and dismiss act only on inbox rows; restore recovers a mis-triaged todo
// from dismissed or someday back to inbox.
var triageVerdicts = map[string]triageRule{
	"accept":  {target: todo.StateTodo, sources: []todo.State{todo.StateInbox}},
	"someday": {target: todo.StateSomeday, sources: []todo.State{todo.StateInbox}},
	"dismiss": {target: todo.StateDismissed, sources: []todo.State{todo.StateInbox}},
	"restore": {target: todo.StateInbox, sources: []todo.State{todo.StateDismissed, todo.StateSomeday}},
}

// errInvalidTriageState signals a todo that exists but is in a state the
// requested verdict cannot act on.
var errInvalidTriageState = errors.New("invalid state for verdict")

// TriageTodoInput is the input for triage_todo: the todo to act on, the
// owner's verdict, and accept's optional field overrides. There is no
// created_by scoping — the tool executes the owner's verdict on any
// creator's todo.
type TriageTodoInput struct {
	ID      string  `json:"id" jsonschema:"required" jsonschema_description:"UUID of the todo to triage. Cross-creator by design — the verdict reaches any creator's todo."`
	Verdict string  `json:"verdict" jsonschema:"required" jsonschema_description:"The owner's verdict: 'accept' (inbox → todo), 'someday' (inbox → someday), 'dismiss' (inbox → dismissed), or 'restore' (dismissed|someday → inbox)."`
	Project string  `json:"project,omitempty" jsonschema_description:"Project id, exact slug, or exact title (case-insensitive); unresolvable values are ignored. Valid only with verdict accept."`
	Due     *string `json:"due,omitempty" jsonschema_description:"Due date YYYY-MM-DD. Valid only with verdict accept; omitted, the captured due is preserved."`
	Energy  *string `json:"energy,omitempty" jsonschema_description:"Energy level, one of: \"high\", \"medium\", \"low\". Valid only with verdict accept; omitted, the captured energy is preserved."`
	As      string  `json:"as,omitempty" jsonschema_description:"Self-identification — the agent executing the owner's verdict. Attributed as the actor on the triage audit event."`
}

// TriageTodoOutput echoes the persisted row after the verdict: its new
// state and the persisted project_id (null when the row has no project),
// due, and energy.
type TriageTodoOutput struct {
	ID        string  `json:"id"`
	State     string  `json:"state"`
	ProjectID *string `json:"project_id"`
	Due       *string `json:"due,omitempty"`
	Energy    *string `json:"energy,omitempty"`
	OK        bool    `json:"ok"`
}

// triagePlan is the validated, database-free projection of a
// TriageTodoInput: verdict rule resolved, id and due parsed, energy checked.
// project stays the raw reference — resolving it needs the database and
// happens in the handler.
type triagePlan struct {
	verdict string
	rule    triageRule
	id      uuid.UUID
	due     *time.Time
	energy  *string
	project string
}

// validateTriageInput runs every handler-level check before any mutation:
// verdict allowlist, accept-only optional fields, id syntax, energy
// vocabulary, and due format. Empty-string optionals count as absent,
// mirroring capture_inbox.
func validateTriageInput(in *TriageTodoInput) (triagePlan, error) {
	rule, ok := triageVerdicts[in.Verdict]
	if !ok {
		return triagePlan{}, fmt.Errorf("invalid verdict %q: must be one of accept, someday, dismiss, restore", in.Verdict)
	}

	hasProject := in.Project != ""
	hasDue := in.Due != nil && *in.Due != ""
	hasEnergy := in.Energy != nil && *in.Energy != ""
	if in.Verdict != "accept" && (hasProject || hasDue || hasEnergy) {
		return triagePlan{}, fmt.Errorf("project, due, and energy are valid only with verdict accept, got verdict %q", in.Verdict)
	}

	id, err := uuid.Parse(in.ID)
	if err != nil {
		return triagePlan{}, fmt.Errorf("invalid id %q: %w", in.ID, err)
	}

	plan := triagePlan{verdict: in.Verdict, rule: rule, id: id, project: in.Project}
	if hasEnergy {
		if !isValidEnergy(*in.Energy) {
			return triagePlan{}, fmt.Errorf("energy must be one of: high, medium, low (got %q)", *in.Energy)
		}
		plan.energy = in.Energy
	}
	if hasDue {
		t, parseErr := time.Parse(time.DateOnly, *in.Due)
		if parseErr != nil {
			return triagePlan{}, fmt.Errorf("invalid due date %q (expected YYYY-MM-DD): %w", *in.Due, parseErr)
		}
		plan.due = &t
	}
	return plan, nil
}

func (s *Server) triageTodo(ctx context.Context, _ *mcp.CallToolRequest, in TriageTodoInput) (*mcp.CallToolResult, TriageTodoOutput, error) {
	plan, err := validateTriageInput(&in)
	if err != nil {
		return nil, TriageTodoOutput{}, err
	}

	// Resolve the accept-only project reference before the transaction, the
	// way capture_inbox does. nil (unresolvable) never clears an existing
	// link — TriageAccept's COALESCE preserves the captured value.
	var projectID *uuid.UUID
	if plan.project != "" {
		projectID = s.resolveProjectID(ctx, plan.project)
	}

	// The whole verdict runs inside withActorTx: the FOR UPDATE state check
	// and the update share one transaction (no check-then-act race), and the
	// state-change audit event is attributed to the caller.
	var item *todo.Item
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		store := s.todos.WithTx(tx)

		cur, err := store.StateForUpdate(ctx, plan.id)
		if err != nil {
			if errors.Is(err, todo.ErrNotFound) {
				return fmt.Errorf("no todo %s: it does not exist", plan.id)
			}
			return err
		}
		if !slices.Contains(plan.rule.sources, cur) {
			return fmt.Errorf("todo %s is in state %s and verdict %s acts only on state %s: %w",
				plan.id, cur, plan.verdict, sourcesLabel(plan.rule.sources), errInvalidTriageState)
		}

		if plan.verdict == "accept" {
			item, err = store.TriageAccept(ctx, plan.id, &todo.TriageAcceptParams{
				ProjectID: projectID,
				Due:       plan.due,
				Energy:    plan.energy,
			})
		} else {
			item, err = store.UpdateState(ctx, plan.id, plan.rule.target)
		}
		if err != nil {
			return fmt.Errorf("triaging todo %s to %s: %w", plan.id, plan.rule.target, err)
		}
		return nil
	})
	if err != nil {
		return nil, TriageTodoOutput{}, err
	}

	out := TriageTodoOutput{ID: item.ID.String(), State: string(item.State), Energy: item.Energy, OK: true}
	if item.ProjectID != nil {
		out.ProjectID = new(item.ProjectID.String())
	}
	if item.Due != nil {
		out.Due = new(item.Due.Format(time.DateOnly))
	}
	return nil, out, nil
}

// sourcesLabel renders a rule's source states for the invalid-state message
// ("inbox", or "dismissed or someday").
func sourcesLabel(sources []todo.State) string {
	labels := make([]string, len(sources))
	for i, st := range sources {
		labels[i] = string(st)
	}
	return strings.Join(labels, " or ")
}
