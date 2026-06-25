// Copyright 2026 Koopa. All rights reserved.

// recurrence.go holds set_todo_recurrence — the agent write path that turns a
// todo it created into a recurring one (weekday-mode or interval-mode) or clears
// the schedule. Recurrence drives the compute-on-read due-today surface
// (todo.RecurringItemsDueToday); resolving a recurring todo to done completes
// today's occurrence (resolve_todo) rather than ending it.

package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/todo"
)

// weekdayBits maps a lowercase weekday abbreviation to its bit in the
// recur_weekdays mask (Mon=bit0 .. Sun=bit6, matching ISODOW-1).
var weekdayBits = map[string]int16{
	"mon": 1, "tue": 2, "wed": 4, "thu": 8, "fri": 16, "sat": 32, "sun": 64,
}

// orderedWeekdays lists the abbreviations in week order for stable output.
var orderedWeekdays = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

// recurUnits is the closed set of interval-mode units (mirrors the
// recur_unit CHECK in the todos schema).
var recurUnits = map[string]struct{}{
	"days": {}, "weeks": {}, "months": {}, "years": {},
}

// SetTodoRecurrenceInput is the input for the set_todo_recurrence tool.
type SetTodoRecurrenceInput struct {
	TodoID   string   `json:"todo_id" jsonschema:"required" jsonschema_description:"UUID of a todo YOU created (created_by = your resolved identity). Caller-scoped — setting recurrence on another agent's todo returns not-found and changes nothing."`
	Weekdays []string `json:"weekdays,omitempty" jsonschema_description:"Weekday-mode: the days the todo recurs, any of mon,tue,wed,thu,fri,sat,sun. E.g. [\"mon\",\"tue\",\"wed\",\"thu\",\"fri\",\"sat\"] for Mon-Sat, or all seven for daily. Mutually exclusive with interval/unit."`
	Interval *int     `json:"interval,omitempty" jsonschema_description:"Interval-mode: recur every N units measured from the last completion (self-pacing). Requires unit; must be > 0. Mutually exclusive with weekdays."`
	Unit     *string  `json:"unit,omitempty" jsonschema_description:"Interval-mode unit: days, weeks, months, or years. Required with interval."`
	Clear    bool     `json:"clear,omitempty" jsonschema_description:"Set true to remove any recurrence, making the todo a one-shot again. Mutually exclusive with weekdays and interval."`
	As       string   `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making the call. The write is scoped to this resolved identity; you can only schedule todos you created."`
}

// SetTodoRecurrenceOutput is the output of the set_todo_recurrence tool.
type SetTodoRecurrenceOutput struct {
	ID         string `json:"id"`
	Recurrence string `json:"recurrence"` // human-readable summary of the schedule now set
	OK         bool   `json:"ok"`
}

func (s *Server) setTodoRecurrence(ctx context.Context, _ *mcp.CallToolRequest, in SetTodoRecurrenceInput) (*mcp.CallToolResult, SetTodoRecurrenceOutput, error) {
	id, err := uuid.Parse(in.TodoID)
	if err != nil {
		return nil, SetTodoRecurrenceOutput{}, fmt.Errorf("invalid todo_id %q: %w", in.TodoID, err)
	}

	rec, desc, err := buildRecurrence(in)
	if err != nil {
		return nil, SetTodoRecurrenceOutput{}, err
	}

	caller := s.callerIdentity(ctx)
	if err := s.todos.SetRecurrence(ctx, id, caller, rec); err != nil {
		if errors.Is(err, todo.ErrNotFound) {
			return nil, SetTodoRecurrenceOutput{}, fmt.Errorf("no todo %s created by %q: it does not exist or you did not create it", id, caller)
		}
		return nil, SetTodoRecurrenceOutput{}, fmt.Errorf("setting recurrence for task %s: %w", id, err)
	}

	return nil, SetTodoRecurrenceOutput{ID: id.String(), Recurrence: desc, OK: true}, nil
}

// buildRecurrence validates that exactly one mode is requested (weekdays,
// interval, or clear) and converts it to a todo.Recurrence plus a human-readable
// description. The mutual exclusivity here mirrors chk_todo_recurrence, but the
// tool validates first so the caller gets a 400-style message, not a CHECK error.
func buildRecurrence(in SetTodoRecurrenceInput) (todo.Recurrence, string, error) {
	hasWeekdays := len(in.Weekdays) > 0
	hasInterval := in.Interval != nil || in.Unit != nil

	modes := 0
	for _, set := range []bool{hasWeekdays, hasInterval, in.Clear} {
		if set {
			modes++
		}
	}
	if modes == 0 {
		return todo.Recurrence{}, "", fmt.Errorf("specify exactly one of: weekdays, interval+unit, or clear=true")
	}
	if modes > 1 {
		return todo.Recurrence{}, "", fmt.Errorf("weekdays, interval, and clear are mutually exclusive — set exactly one")
	}

	switch {
	case in.Clear:
		return todo.Recurrence{}, "none", nil
	case hasWeekdays:
		mask, days, err := weekdaysToMask(in.Weekdays)
		if err != nil {
			return todo.Recurrence{}, "", err
		}
		return todo.Recurrence{Weekdays: &mask}, "weekdays: " + strings.Join(days, ","), nil
	default: // interval
		if in.Interval == nil || in.Unit == nil {
			return todo.Recurrence{}, "", fmt.Errorf("interval-mode needs both interval and unit")
		}
		if *in.Interval <= 0 || *in.Interval > maxRecurInterval {
			return todo.Recurrence{}, "", fmt.Errorf("interval must be in [1, %d], got %d", maxRecurInterval, *in.Interval)
		}
		unit := strings.ToLower(*in.Unit)
		if _, ok := recurUnits[unit]; !ok {
			return todo.Recurrence{}, "", fmt.Errorf("unsupported unit %q (supported: days, weeks, months, years)", *in.Unit)
		}
		interval := int32(*in.Interval) // #nosec G115 -- bounded to [1, maxRecurInterval] above
		return todo.Recurrence{Interval: &interval, Unit: &unit}, fmt.Sprintf("every %d %s", interval, unit), nil
	}
}

// maxRecurInterval bounds the interval-mode count so the int32 cast cannot
// overflow. No real "every N units" schedule approaches this ceiling.
const maxRecurInterval = 10_000

// weekdaysToMask converts weekday abbreviations to the recur_weekdays bitmask
// and the deduplicated, week-ordered list used in the response. Unknown days are
// rejected; duplicates collapse.
func weekdaysToMask(weekdays []string) (mask int16, days []string, err error) {
	seen := make(map[string]struct{}, len(weekdays))
	for _, w := range weekdays {
		key := strings.ToLower(strings.TrimSpace(w))
		bit, ok := weekdayBits[key]
		if !ok {
			return 0, nil, fmt.Errorf("unknown weekday %q (use mon,tue,wed,thu,fri,sat,sun)", w)
		}
		mask |= bit
		seen[key] = struct{}{}
	}
	if mask == 0 {
		return 0, nil, fmt.Errorf("weekdays must name at least one day")
	}
	days = make([]string, 0, len(seen))
	for _, d := range orderedWeekdays {
		if _, ok := seen[d]; ok {
			days = append(days, d)
		}
	}
	return mask, days, nil
}
