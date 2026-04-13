// Package consolidation is the secondary process layer that writes
// historical snapshots into the synthesis table. It is the ONLY
// layer that should call synthesis.Store.Create.
//
// Consolidation is deliberately constrained:
//
//   - Pure deterministic Go — no LLM calls, no MCP dispatch, no
//     network I/O beyond the database.
//   - Read primary tables, write one secondary table. Primary state
//     is never modified by a consolidation run.
//   - Re-runnable: the same primary state produces the same
//     synthesis row (idempotent via ON CONFLICT DO NOTHING on the
//     synthesis unique indexes). Primary state changes produce a
//     new synthesis row (historical accumulation), not an update.
//
// First slice: RunWeekly is the only phase. It consolidates a single
// week into one synthesis row of kind=weekly_review. Future phases
// (goal snapshots, concept mastery snapshots) are not in this slice.
//
// Invocation model: RunWeekly is called from an admin HTTP endpoint
// (POST /api/admin/consolidate/weekly) as a manual replay trigger.
// When Wave 3 introduces a cron scheduler, the cron invokes the same
// function — the consolidation layer has no opinion about who
// triggers it, only that the trigger is NOT a live read handler.
package consolidation

import (
	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/learning"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// PrimaryReader bundles the read-only access to primary state a
// consolidation phase needs. Passing one aggregate struct instead of
// N separate store arguments keeps RunWeekly's signature stable when
// future phases need more stores, and makes it obvious at the call
// site that consolidation only consumes read paths on primary.
//
// These are concrete Store types, not interfaces, per the project's
// consumer-defines-interface rule — consolidation is the only
// consumer today, and defining an interface speculatively would just
// be noise.
type PrimaryReader struct {
	Tasks    *task.Store
	Journal  *journal.Store
	Learning *learning.Store
}

// NewPrimaryReader constructs a PrimaryReader from already-constructed
// stores. Does not open connections or allocate — it is a thin
// grouping type for wiring clarity in cmd/app/main.go.
func NewPrimaryReader(
	tasks *task.Store,
	jrnl *journal.Store,
	learn *learning.Store,
) *PrimaryReader {
	return &PrimaryReader{
		Tasks:    tasks,
		Journal:  jrnl,
		Learning: learn,
	}
}
