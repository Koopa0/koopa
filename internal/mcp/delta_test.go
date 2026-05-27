package mcp

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	agentnote "github.com/Koopa0/koopa/internal/agent/note"
	"github.com/Koopa0/koopa/internal/todo"
)

// TestSessionDeltaOutput_WireShape pins the top-level key set of
// SessionDeltaOutput and asserts the three slice fields encode as `[]`
// when populated, not as `null`. Concrete element shapes belong to
// internal/todo and internal/agent/note; we only pin the wrapper.
func TestSessionDeltaOutput_WireShape(t *testing.T) {
	t.Parallel()

	expectedKeys := []string{
		"since",
		"todos_created",
		"todos_completed",
		"agent_notes",
		"session_count",
	}

	tests := []struct {
		name string
		out  SessionDeltaOutput
	}{
		{
			name: "empty — all five keys present, slices = []",
			out: SessionDeltaOutput{
				Since:          "2026-05-26",
				TodosCreated:   []todo.CreatedDetail{},
				TodosCompleted: []todo.CompletedDetail{},
				AgentNotes:     []agentnote.Note{},
				SessionCount:   0,
			},
		},
		{
			name: "populated — slice cardinality preserved",
			out: SessionDeltaOutput{
				Since:          "2026-05-26",
				TodosCreated:   []todo.CreatedDetail{{}, {}},
				TodosCompleted: []todo.CompletedDetail{{}},
				AgentNotes:     []agentnote.Note{{}, {}, {}},
				SessionCount:   2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parsed := marshalToKeyMap(t, tt.out)

			gotKeys := make([]string, 0, len(parsed))
			for k := range parsed {
				gotKeys = append(gotKeys, k)
			}
			slices.Sort(gotKeys)
			wantKeys := slices.Clone(expectedKeys)
			slices.Sort(wantKeys)
			if diff := cmp.Diff(wantKeys, gotKeys); diff != "" {
				t.Errorf("SessionDeltaOutput top-level key set mismatch (-want +got):\n%s", diff)
			}

			for _, sliceKey := range []string{"todos_created", "todos_completed", "agent_notes"} {
				raw, ok := parsed[sliceKey]
				if !ok {
					continue
				}
				if string(raw) == "null" {
					t.Errorf("SessionDeltaOutput[%q] = null, want JSON array", sliceKey)
					continue
				}
				if !strings.HasPrefix(string(raw), "[") {
					t.Errorf("SessionDeltaOutput[%q] = %s, want JSON array", sliceKey, raw)
				}
			}
		})
	}
}

// TestNewSessionDeltaOutput_NilSlicesBecomeEmptyArrays directly guards
// the production builder in delta.go that the sessionDelta handler
// depends on. Calling the builder with nil for every slice input MUST
// yield an output whose marshaled JSON has `[]` (never `null`) for each
// slice field. This is the load-bearing regression guard: if anyone
// removes the nil checks inside newSessionDeltaOutput, or weakens its
// contract, this test fails. Because the handler is required to route
// through this builder (documented in newSessionDeltaOutput's doc
// comment and enforced by code review), guarding the builder guards the
// handler's wire output.
func TestNewSessionDeltaOutput_NilSlicesBecomeEmptyArrays(t *testing.T) {
	t.Parallel()

	out := newSessionDeltaOutput("2026-05-26", nil, nil, nil, 0)

	// Slice values themselves must be non-nil so downstream callers
	// (including, but not limited to, json.Marshal) see [] semantics.
	if out.TodosCreated == nil {
		t.Errorf("newSessionDeltaOutput(nil…).TodosCreated = nil, want non-nil empty slice")
	}
	if out.TodosCompleted == nil {
		t.Errorf("newSessionDeltaOutput(nil…).TodosCompleted = nil, want non-nil empty slice")
	}
	if out.AgentNotes == nil {
		t.Errorf("newSessionDeltaOutput(nil…).AgentNotes = nil, want non-nil empty slice")
	}

	// The wire shape is the contract that frontend/agent consumers
	// actually depend on — assert at the JSON layer too.
	parsed := marshalToKeyMap(t, out)
	for _, key := range []string{"todos_created", "todos_completed", "agent_notes"} {
		raw, ok := parsed[key]
		if !ok {
			t.Errorf("newSessionDeltaOutput marshaled output missing key %q", key)
			continue
		}
		if string(raw) == "null" {
			t.Errorf("newSessionDeltaOutput[%q] = null, want []", key)
			continue
		}
		if !strings.HasPrefix(string(raw), "[") {
			t.Errorf("newSessionDeltaOutput[%q] = %s, want JSON array", key, raw)
		}
	}
}

// TestNewSessionDeltaOutput_NonNilSlicesPreserved asserts the builder
// does not mutate or replace non-nil inputs. Without this guard, a
// future "simplification" that always assigns []T{} would silently
// drop store data on the floor.
func TestNewSessionDeltaOutput_NonNilSlicesPreserved(t *testing.T) {
	t.Parallel()

	createdIn := []todo.CreatedDetail{{}, {}}
	completedIn := []todo.CompletedDetail{{}}
	notesIn := []agentnote.Note{{}, {}, {}}

	out := newSessionDeltaOutput("2026-05-26", createdIn, completedIn, notesIn, 4)

	if got, want := len(out.TodosCreated), len(createdIn); got != want {
		t.Errorf("newSessionDeltaOutput preserved TodosCreated len = %d, want %d", got, want)
	}
	if got, want := len(out.TodosCompleted), len(completedIn); got != want {
		t.Errorf("newSessionDeltaOutput preserved TodosCompleted len = %d, want %d", got, want)
	}
	if got, want := len(out.AgentNotes), len(notesIn); got != want {
		t.Errorf("newSessionDeltaOutput preserved AgentNotes len = %d, want %d", got, want)
	}
	if out.Since != "2026-05-26" {
		t.Errorf("newSessionDeltaOutput Since = %q, want %q", out.Since, "2026-05-26")
	}
	if out.SessionCount != 4 {
		t.Errorf("newSessionDeltaOutput SessionCount = %d, want %d", out.SessionCount, 4)
	}
}
