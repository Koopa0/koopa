// Copyright 2026 Koopa. All rights reserved.

// Package stats aggregates cross-feature statistics for the admin
// dashboard. All queries are sqlc-generated; see internal/stats/query.sql.
package stats

import (
	"context"
	"fmt"
	"slices"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Koopa0/koopa/internal/db"
)

// Store aggregates stats from all platform tables.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// ProcessRunKinds lists every process_runs.kind value the admin dashboard
// reports on. Order is cosmetic: crawl (most frequent) first,
// agent_schedule second. Must match the CHECK constraint on
// process_runs.kind in migrations/001_initial.up.sql.
var ProcessRunKinds = []string{"crawl", "agent_schedule"}

// Overview returns aggregated stats across all platform data sources.
// Queries run concurrently via errgroup since they are independent.
func (s *Store) Overview(ctx context.Context) (*Overview, error) {
	o := &Overview{
		Contents:    ContentStats{ByStatus: map[string]int{}, ByType: map[string]int{}},
		Collected:   CollectedStats{ByStatus: map[string]int{}},
		ProcessRuns: make(map[string]ProcessRunStats, len(ProcessRunKinds)),
		Projects:    ProjectStats{ByStatus: map[string]int{}},
		Activity:    ActivityStats{BySource: map[string]int{}},
	}
	// Seed zero entries so every kind is always present in the response,
	// even when no rows exist yet.
	for _, k := range ProcessRunKinds {
		o.ProcessRuns[k] = ProcessRunStats{ByStatus: map[string]int{}}
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return s.queryContentStats(ctx, &o.Contents) })
	g.Go(func() error { return s.queryCollectedStats(ctx, &o.Collected) })
	g.Go(func() error { return s.queryFeedStats(ctx, &o.Feeds) })
	// ProcessRuns queries share the o.ProcessRuns map — run them serially
	// in one goroutine to avoid concurrent map writes (race). The per-kind
	// query is fast (one COUNT per status) so serialising within a single
	// goroutine costs nothing relative to the parallel outer work.
	g.Go(func() error {
		for _, k := range ProcessRunKinds {
			if err := s.queryProcessRunStats(ctx, k, o.ProcessRuns); err != nil {
				return err
			}
		}
		return nil
	})
	g.Go(func() error { return s.queryProjectStats(ctx, &o.Projects) })
	g.Go(func() error { return s.queryActivityStats(ctx, &o.Activity) })

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return o, nil
}

func (s *Store) queryContentStats(ctx context.Context, cs *ContentStats) error {
	rows, err := s.q.StatsContentsByStatusType(ctx)
	if err != nil {
		return fmt.Errorf("contents stats: %w", err)
	}
	for i := range rows {
		count := int(rows[i].Count)
		cs.Total += count
		cs.ByStatus[rows[i].Status] += count
		cs.ByType[rows[i].Type] += count
		if rows[i].Status == "published" {
			cs.Published += count
		}
	}
	return nil
}

func (s *Store) queryCollectedStats(ctx context.Context, cs *CollectedStats) error {
	rows, err := s.q.StatsFeedEntriesByStatus(ctx)
	if err != nil {
		return fmt.Errorf("feed_entries stats: %w", err)
	}
	for i := range rows {
		count := int(rows[i].Count)
		cs.Total += count
		cs.ByStatus[rows[i].Status] += count
	}
	return nil
}

func (s *Store) queryFeedStats(ctx context.Context, fs *FeedStats) error {
	row, err := s.q.StatsFeedCounts(ctx)
	if err != nil {
		return fmt.Errorf("feeds stats: %w", err)
	}
	fs.Total = int(row.Total)
	fs.Enabled = int(row.Enabled)
	return nil
}

func (s *Store) queryProcessRunStats(ctx context.Context, kind string, out map[string]ProcessRunStats) error {
	rows, err := s.q.StatsProcessRunsByStatus(ctx, kind)
	if err != nil {
		return fmt.Errorf("process_runs[%s] stats: %w", kind, err)
	}
	// Start from the seeded zero entry so ByStatus map is never nil.
	fs := out[kind]
	for i := range rows {
		count := int(rows[i].Count)
		fs.Total += count
		fs.ByStatus[rows[i].Status] += count
	}
	out[kind] = fs
	return nil
}

func (s *Store) queryProjectStats(ctx context.Context, ps *ProjectStats) error {
	rows, err := s.q.StatsProjectsByStatus(ctx)
	if err != nil {
		return fmt.Errorf("projects stats: %w", err)
	}
	for i := range rows {
		count := int(rows[i].Count)
		ps.Total += count
		ps.ByStatus[rows[i].Status] += count
	}
	return nil
}

func (s *Store) queryActivityStats(ctx context.Context, as *ActivityStats) error {
	window, err := s.q.StatsActivityWindow(ctx)
	if err != nil {
		return fmt.Errorf("activity window: %w", err)
	}
	as.Total = int(window.Total)
	as.Last24h = int(window.Last24h)
	as.Last7d = int(window.Last7d)

	rows, err := s.q.StatsActivityBySource(ctx)
	if err != nil {
		return fmt.Errorf("activity by source: %w", err)
	}
	for i := range rows {
		as.BySource[rows[i].Source] += int(rows[i].Count)
	}
	return nil
}

// Drift compares activity distribution (last N days) vs active goals by area.
func (s *Store) Drift(ctx context.Context, days int) (*DriftReport, error) {
	goalsByArea, totalGoals, err := s.queryGoalsByArea(ctx)
	if err != nil {
		return nil, err
	}

	eventsByArea, totalEvents, err := s.queryEventsByArea(ctx, days)
	if err != nil {
		return nil, err
	}

	areas := computeAreaDrift(goalsByArea, totalGoals, eventsByArea, totalEvents)

	return &DriftReport{
		Period: fmt.Sprintf("last %d days", days),
		Areas:  areas,
	}, nil
}

func (s *Store) queryGoalsByArea(ctx context.Context) (map[string]int, int, error) { //nolint:gocritic // 3 returns are values+total+error, named returns would shadow local := bindings
	rows, err := s.q.StatsGoalsByArea(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("querying goals by area: %w", err)
	}
	byArea := map[string]int{}
	total := 0
	for i := range rows {
		count := int(rows[i].Count)
		byArea[rows[i].Area] = count
		total += count
	}
	return byArea, total, nil
}

func (s *Store) queryEventsByArea(ctx context.Context, days int) (map[string]int, int, error) { //nolint:gocritic // 3 returns are values+total+error, named returns would shadow local := bindings
	rows, err := s.q.StatsEventsByArea(ctx, int32(days)) // #nosec G115 -- bounded by caller
	if err != nil {
		return nil, 0, fmt.Errorf("querying events by area: %w", err)
	}
	byArea := map[string]int{}
	total := 0
	for i := range rows {
		count := int(rows[i].Count)
		byArea[rows[i].Area] = count
		total += count
	}
	return byArea, total, nil
}

// computeAreaDrift merges goal and event distributions, computes percentages, and sorts by absolute drift.
func computeAreaDrift(goalsByArea map[string]int, totalGoals int, eventsByArea map[string]int, totalEvents int) []AreaDrift {
	allAreas := map[string]struct{}{}
	for a := range goalsByArea {
		allAreas[a] = struct{}{}
	}
	for a := range eventsByArea {
		allAreas[a] = struct{}{}
	}

	areas := make([]AreaDrift, 0, len(allAreas))
	for area := range allAreas {
		goals := goalsByArea[area]
		events := eventsByArea[area]
		var goalPct, eventPct float64
		if totalGoals > 0 {
			goalPct = float64(goals) / float64(totalGoals) * 100
		}
		if totalEvents > 0 {
			eventPct = float64(events) / float64(totalEvents) * 100
		}
		areas = append(areas, AreaDrift{
			Area:         area,
			ActiveGoals:  goals,
			EventCount:   events,
			EventPercent: eventPct,
			GoalPercent:  goalPct,
			DriftPercent: eventPct - goalPct,
		})
	}

	slices.SortFunc(areas, func(a, b AreaDrift) int {
		absA := a.DriftPercent
		if absA < 0 {
			absA = -absA
		}
		absB := b.DriftPercent
		if absB < 0 {
			absB = -absB
		}
		if absB > absA {
			return 1
		}
		if absA > absB {
			return -1
		}
		return 0
	})

	return areas
}

// ProcessRunsSince returns process_runs counts by status since the given
// time within a single kind, optionally filtered by run name and status.
func (s *Store) ProcessRunsSince(ctx context.Context, since time.Time, kind string, name, status *string) (*ProcessRunSummary, error) {
	row, err := s.q.StatsProcessRunsSummary(ctx, db.StatsProcessRunsSummaryParams{
		Kind:   kind,
		Since:  since,
		Name:   name,
		Status: status,
	})
	if err != nil {
		return nil, fmt.Errorf("querying process_runs[%s] stats since %v: %w", kind, since, err)
	}
	return &ProcessRunSummary{
		Total:     int(row.Total),
		Completed: int(row.Completed),
		Failed:    int(row.Failed),
		Running:   int(row.Running),
		Pending:   int(row.Pending),
	}, nil
}

// RecentProcessRuns returns recent process_runs within a single kind over a
// time window, optionally filtered by name and status.
func (s *Store) RecentProcessRuns(ctx context.Context, since time.Time, kind string, name, status *string, limit int) ([]RecentProcessRun, error) {
	rows, err := s.q.StatsRecentProcessRuns(ctx, db.StatsRecentProcessRunsParams{
		Kind:       kind,
		Since:      since,
		Name:       name,
		Status:     status,
		MaxResults: int32(limit), // #nosec G115 -- bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("querying recent process_runs[%s]: %w", kind, err)
	}
	runs := make([]RecentProcessRun, 0, len(rows))
	for i := range rows {
		r := RecentProcessRun{
			ID:        rows[i].ID.String(),
			Name:      rows[i].Name,
			Status:    rows[i].Status,
			Error:     rows[i].Error,
			CreatedAt: rows[i].CreatedAt.Format(time.RFC3339),
		}
		if rows[i].EndedAt != nil {
			s := rows[i].EndedAt.Format(time.RFC3339)
			r.EndedAt = &s
		}
		runs = append(runs, r)
	}
	return runs, nil
}

// SystemHealth returns the snapshot served at GET /api/admin/system/health.
//
// Composes feed health, recent pipeline activity (last 24h), and core entity
// counts.
func (s *Store) SystemHealth(ctx context.Context) (*SystemHealthSnapshot, error) {
	out := &SystemHealthSnapshot{
		Feeds:     FeedHealth{FailingFeeds: []FailingFeed{}},
		Pipelines: PipelineHealth{},
		Database:  DatabaseStats{},
	}

	feedCounts, err := s.q.StatsFeedHealthCounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying feed counts: %w", err)
	}
	out.Feeds.Total = int(feedCounts.Total)
	out.Feeds.Healthy = int(feedCounts.Healthy)
	out.Feeds.Failing = int(feedCounts.Failing)

	failingRows, err := s.q.StatsFailingFeeds(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying failing feeds: %w", err)
	}
	for i := range failingRows {
		ff := FailingFeed{
			Name:  failingRows[i].Name,
			Error: failingRows[i].LastError,
		}
		if failingRows[i].LastFetchedAt != nil {
			ff.Since = failingRows[i].LastFetchedAt.Format(time.RFC3339)
		}
		out.Feeds.FailingFeeds = append(out.Feeds.FailingFeeds, ff)
	}

	since := time.Now().Add(-24 * time.Hour)
	pipeline, err := s.q.StatsProcessRunsRecent(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("querying process_runs recent: %w", err)
	}
	out.Pipelines.RecentRuns = int(pipeline.RecentRuns)
	out.Pipelines.Failed = int(pipeline.Failed)
	if !pipeline.LastRunAt.IsZero() {
		s := pipeline.LastRunAt.Format(time.RFC3339)
		out.Pipelines.LastRunAt = &s
	}

	dbCounts, err := s.q.StatsDatabaseCounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying database counts: %w", err)
	}
	out.Database.ContentsCount = int(dbCounts.ContentsCount)
	out.Database.TodosCount = int(dbCounts.TodosCount)

	return out, nil
}
