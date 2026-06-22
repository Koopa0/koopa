// Copyright 2026 Koopa. All rights reserved.

// Package stats provides aggregated platform statistics for the admin
// dashboard. It is a READ-ONLY aggregator — no writes, no mutations.
// Every method runs N independent queries against existing feature
// tables (contents, collected, feeds, process_runs, projects,
// activity_events, goals) and assembles a response shape
// matched to the frontend dashboard contract.
//
// File map:
//   - stats.go (this file) — wire-contract types only.
//   - store.go             — the aggregator. Each *Stats subtype has
//     a dedicated query*Stats helper; failures in one helper fall
//     through to an overall error rather than silently zeroing one
//     section.
//   - handler.go           — thin HTTP wrappers around the store.
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
	Activity    ActivityStats              `json:"activity"`
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
// (crawl or agent_schedule). Used as the value type in Overview.ProcessRuns map.
type ProcessRunStats struct {
	Total    int            `json:"total"`
	ByStatus map[string]int `json:"by_status"`
}

// ProjectStats holds project counts by status.
type ProjectStats struct {
	Total    int            `json:"total"`
	ByStatus map[string]int `json:"by_status"`
}

// ActivityStats holds activity event counts.
type ActivityStats struct {
	Total   int `json:"total"`
	Last24h int `json:"last_24h"`
	Last7d  int `json:"last_7d"`
	// BySource is keyed by the activity event's entity_type (todo, content,
	// note, ...) — the changed entity's kind, not a provenance source.
	BySource map[string]int `json:"by_source"`
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

// RecentProcessRun holds a single process_runs row for the recent runs list.
type RecentProcessRun struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	Error     *string `json:"error,omitempty"`
	CreatedAt string  `json:"created_at"`
	EndedAt   *string `json:"ended_at,omitempty"`
}

// SystemHealthSnapshot is the wire shape served at GET /api/admin/system/health.
// Consumed by the admin shell ribbon, today warnings, and nav counters.
type SystemHealthSnapshot struct {
	Feeds     FeedHealth     `json:"feeds"`
	Pipelines PipelineHealth `json:"pipelines"`
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

// DatabaseStats is the database section of SystemHealthSnapshot — core
// entity counts so a caller scanning health can see at a glance which
// stores are populated.
type DatabaseStats struct {
	ContentsCount int `json:"contents_count"`
	TodosCount    int `json:"todos_count"`
}
