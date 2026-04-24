// Package stats provides aggregated platform statistics for the admin
// dashboard. It is a READ-ONLY aggregator — no writes, no mutations.
// Every method runs N independent queries against existing feature
// tables (contents, collected, feeds, process_runs, projects,
// activity_events, tag_aliases, goals) and assembles a response shape
// matched to the frontend dashboard contract.
//
// File map:
//   - stats.go (this file) — wire-contract types only.
//   - store.go             — the aggregator. Each *Stats subtype has
//     a dedicated query*Stats helper; failures in one helper fall
//     through to an overall error rather than silently zeroing one
//     section.
//   - handler.go           — thin HTTP wrappers around the store.
//
// Load-bearing invariant: NoteStats is currently a no-op — the
// aggregation query isn't wired yet. The dashboard row renders as
// zero; do NOT add a nil check on the frontend that branches on it.
package stats

// Overview contains aggregated stats across all platform data sources.
//
// ProcessRuns is a map keyed by process_runs.kind — currently one of
// "crawl", "agent_schedule". The map is always populated with every valid
// kind (zero-valued stats when no rows exist) so the frontend does not
// need to distinguish "missing key" from "zero runs".
type Overview struct {
	Contents    ContentStats               `json:"contents"`
	Collected   CollectedStats             `json:"collected"`
	Feeds       FeedStats                  `json:"feeds"`
	ProcessRuns map[string]ProcessRunStats `json:"process_runs"`
	Projects    ProjectStats               `json:"projects"`
	Notes       NoteStats                  `json:"notes"`
	Activity    ActivityStats              `json:"activity"`
	Tags        TagStats                   `json:"tags"`
}

// ContentStats holds content counts by status and type.
type ContentStats struct {
	Total     int            `json:"total"`
	ByStatus  map[string]int `json:"by_status"`
	ByType    map[string]int `json:"by_type"`
	Published int            `json:"published"`
}

// CollectedStats holds collected data counts by status.
type CollectedStats struct {
	Total    int            `json:"total"`
	ByStatus map[string]int `json:"by_status"`
}

// FeedStats holds feed subscription stats.
type FeedStats struct {
	Total   int `json:"total"`
	Enabled int `json:"enabled"`
}

// ProcessRunStats holds process_runs counts by status for a single kind
// (flow or agent_schedule). Used as the value type in Overview.ProcessRuns map.
type ProcessRunStats struct {
	Total    int            `json:"total"`
	ByStatus map[string]int `json:"by_status"`
}

// ProjectStats holds project counts by status.
type ProjectStats struct {
	Total    int            `json:"total"`
	ByStatus map[string]int `json:"by_status"`
}

// NoteStats holds counts of note-type contents broken down by note_kind.
type NoteStats struct {
	Total  int            `json:"total"`
	ByType map[string]int `json:"by_type"`
}

// ActivityStats holds activity event counts.
type ActivityStats struct {
	Total    int            `json:"total"`
	Last24h  int            `json:"last_24h"`
	Last7d   int            `json:"last_7d"`
	BySource map[string]int `json:"by_source"`
}

// TagStats holds tag system stats.
type TagStats struct {
	Canonical   int `json:"canonical"`
	Aliases     int `json:"aliases"`
	Unconfirmed int `json:"unconfirmed"`
}

// DriftReport compares activity distribution vs goal areas.
type DriftReport struct {
	Period string      `json:"period"`
	Areas  []AreaDrift `json:"areas"`
}

// AreaDrift shows the gap between goal focus and actual activity for an area.
type AreaDrift struct {
	Area         string  `json:"area"`
	ActiveGoals  int     `json:"active_goals"`
	EventCount   int     `json:"event_count"`
	EventPercent float64 `json:"event_percent"`
	GoalPercent  float64 `json:"goal_percent"`
	DriftPercent float64 `json:"drift_percent"`
}

// LearningDashboard aggregates learning-related metrics.
type LearningDashboard struct {
	Notes    NoteGrowth     `json:"notes"`
	Activity WeeklyActivity `json:"activity"`
	TopTags  []TagCount     `json:"top_tags"`
}

// NoteGrowth tracks note creation over time.
type NoteGrowth struct {
	Total     int            `json:"total"`
	LastWeek  int            `json:"last_week"`
	LastMonth int            `json:"last_month"`
	ByType    map[string]int `json:"by_type"`
}

// WeeklyActivity tracks activity trends.
type WeeklyActivity struct {
	ThisWeek int    `json:"this_week"`
	LastWeek int    `json:"last_week"`
	Trend    string `json:"trend"` // "up", "down", "stable"
}

// TagCount pairs a tag name with its usage count.
type TagCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// ProcessRunSummary holds process_runs counts by status within a time window
// for a specific kind. Used by ProcessRunsSince.
//
// Each of Completed / Failed / Running / Pending is a FILTER count over the
// same (kind, time-window, name, status) selection. When the caller passes
// status=nil all four fields are meaningful; when the caller narrows with
// status="X" only the field matching X carries a non-zero value (everything
// else filters to zero), and Total is the right "how many rows matched" cell.
type ProcessRunSummary struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Running   int `json:"running"`
	Pending   int `json:"pending"`
}

// FeedHealthSummary holds feed health stats.
type FeedHealthSummary struct {
	Total        int `json:"total"`
	Enabled      int `json:"enabled"`
	FailingFeeds int `json:"failing_feeds"`
}

// RecentProcessRun holds a single process_runs row for the recent runs list.
type RecentProcessRun struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	Error     *string `json:"error,omitempty"`
	CreatedAt string  `json:"created_at"`
	EndedAt   *string `json:"ended_at,omitempty"`
}

// ProcessRunNameSummary holds per-name aggregated stats within a single kind.
// For kind=crawl this is per-collector name (e.g. feed_fetch); for
// agent_schedule it is per-schedule.
type ProcessRunNameSummary struct {
	Name       string  `json:"name"`
	Total      int     `json:"total"`
	Completed  int     `json:"completed"`
	Failed     int     `json:"failed"`
	Running    int     `json:"running"`
	LastRunAt  *string `json:"last_run_at,omitempty"`
	LastStatus *string `json:"last_status,omitempty"`
}

// SystemHealthSnapshot is the legacy shape used by the Store layer for
// internal dashboards. The admin /system/health surface now lives in
// internal/systemhealth and returns its own 4-domain envelope.
type SystemHealthSnapshot struct {
	Feeds     FeedHealth     `json:"feeds"`
	Pipelines PipelineHealth `json:"pipelines"`
	AIBudget  AIBudget       `json:"ai_budget"`
	Database  DatabaseStats  `json:"database"`
}

// FeedHealth is the feed health section of SystemHealthSnapshot.
type FeedHealth struct {
	Total        int           `json:"total"`
	Healthy      int           `json:"healthy"`
	Failing      int           `json:"failing"`
	FailingFeeds []FailingFeed `json:"failing_feeds"`
}

// FailingFeed is one failing feed entry. Since uses last_fetched_at as a
// proxy for "when did this feed start failing" since the schema does not
// track first_failed_at separately.
type FailingFeed struct {
	Name  string `json:"name"`
	Error string `json:"error"`
	Since string `json:"since,omitempty"`
}

// PipelineHealth is the pipeline section of SystemHealthSnapshot.
// Counts cover the last 24h of process_runs across every kind.
type PipelineHealth struct {
	RecentRuns int     `json:"recent_runs"`
	Failed     int     `json:"failed"`
	LastRunAt  *string `json:"last_run_at"`
}

// AIBudget is the AI token budget section of SystemHealthSnapshot.
// Not yet wired to a real source — both fields return zero. Reserved
// for the SystemHealthComponent contract so the frontend does not need
// a conditional rendering branch.
type AIBudget struct {
	TodayTokens int `json:"today_tokens"`
	DailyLimit  int `json:"daily_limit"`
}

// DatabaseStats is the database section of SystemHealthSnapshot.
type DatabaseStats struct {
	ContentsCount int `json:"contents_count"`
	TodosCount    int `json:"todos_count"`
	NotesCount    int `json:"notes_count"`
}
