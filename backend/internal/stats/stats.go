// Package stats provides aggregated platform statistics for the admin dashboard.
package stats

// Overview contains aggregated stats across all platform data sources.
type Overview struct {
	Contents  ContentStats   `json:"contents"`
	Collected CollectedStats `json:"collected"`
	Feeds     FeedStats      `json:"feeds"`
	FlowRuns  FlowRunStats   `json:"flow_runs"`
	Projects  ProjectStats   `json:"projects"`
	Reviews   ReviewStats    `json:"reviews"`
	Notes     NoteStats      `json:"notes"`
	Activity  ActivityStats  `json:"activity"`
	Spaced    SpacedStats    `json:"spaced"`
	Sources   SourceStats    `json:"sources"`
	Tags      TagStats       `json:"tags"`
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

// FlowRunStats holds AI flow run counts by status.
type FlowRunStats struct {
	Total    int            `json:"total"`
	ByStatus map[string]int `json:"by_status"`
}

// ProjectStats holds project counts by status.
type ProjectStats struct {
	Total    int            `json:"total"`
	ByStatus map[string]int `json:"by_status"`
}

// ReviewStats holds review queue stats.
type ReviewStats struct {
	Pending int `json:"pending"`
	Total   int `json:"total"`
}

// NoteStats holds Obsidian note counts.
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

// SpacedStats holds spaced repetition stats.
type SpacedStats struct {
	Enrolled int `json:"enrolled"`
	Due      int `json:"due"`
}

// SourceStats holds Notion source registry stats.
type SourceStats struct {
	Total   int `json:"total"`
	Enabled int `json:"enabled"`
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
	Spaced   SpacedStats    `json:"spaced"`
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
