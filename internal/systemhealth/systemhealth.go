// Package systemhealth composes the GET /api/admin/system/health
// envelope — a cross-domain read-only aggregate that feeds the
// top-of-shell nav counters and Today warnings. The envelope is
// structured as four domain columns (commitment / knowledge / learning
// / coordination), each carrying a set of cell-state badges.
//
// The handler does not own any storage. Each cell reads through a
// narrow consumer interface implemented by the owning domain's Store;
// new cells land by writing a new count method on the source and
// wiring it in cmd/app.
package systemhealth

// Cell is the {count/value, state, reason?} envelope used throughout
// the surface. `count` is an integer cell; `total` optionally pairs
// with `count` on "N of M" cells (today_plan_done). `value` replaces
// `count` for percentage cells. `reason` is rendered as a tooltip when
// the state is not "ok".
type Cell struct {
	Count  *int     `json:"count,omitempty"`
	Total  *int     `json:"total,omitempty"`
	Value  *float64 `json:"value,omitempty"`
	State  string   `json:"state,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

// Commitment — the commitment-domain column.
type Commitment struct {
	TodosOpen     Cell `json:"todos_open"`
	GoalsActive   Cell `json:"goals_active"`
	TodayPlanDone Cell `json:"today_plan_done"`
}

// Knowledge — the knowledge-domain column.
type Knowledge struct {
	ContentsTotal  Cell `json:"contents_total"`
	ReviewQueue    Cell `json:"review_queue"`
	NotesTotal     Cell `json:"notes_total"`
	BookmarksTotal Cell `json:"bookmarks_total"`
	FeedsActive    Cell `json:"feeds_active"`
}

// Learning — the learning-domain column.
type Learning struct {
	ConceptsTotal        Cell `json:"concepts_total"`
	WeakConcepts         Cell `json:"weak_concepts"`
	DueReviews           Cell `json:"due_reviews"`
	HypothesesUnverified Cell `json:"hypotheses_unverified"`
}

// Coordination — the coordination-domain column.
type Coordination struct {
	TasksAwaitingHuman       Cell `json:"tasks_awaiting_human"`
	ProcessRuns24hSuccessPct Cell `json:"process_runs_24h_success_pct"`
	AgentsActive             Cell `json:"agents_active"`
}

// Response is the wire shape for GET /api/admin/system/health.
type Response struct {
	Commitment   Commitment   `json:"commitment"`
	Knowledge    Knowledge    `json:"knowledge"`
	Learning     Learning     `json:"learning"`
	Coordination Coordination `json:"coordination"`
}

// intCell builds an integer-count cell with a given state. The n=0
// path is the common case (zero-initialized placeholders before sources
// fire), but the parameter is kept so source-populated cells can reuse
// the same constructor.
func intCell(n int, state string) Cell { //nolint:unparam // placeholder callers always pass 0
	return Cell{Count: intp(n), State: state}
}

// intCellWithTotal builds a cell that carries both a running count and
// its ceiling (used by today_plan_done).
func intCellWithTotal(count, total int, state string) Cell {
	return Cell{Count: intp(count), Total: intp(total), State: state}
}

// pctCell builds a percentage cell.
func pctCell(v float64, state string) Cell {
	return Cell{Value: &v, State: state}
}

func intp(n int) *int { return &n }
