// Package stats aggregates cross-feature statistics for the admin
// dashboard. All queries are sqlc-generated; see internal/stats/query.sql.
package stats

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store aggregates stats from all platform tables.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// Overview returns aggregated stats across all platform data sources.
// Queries run concurrently via errgroup since they are independent.
func (s *Store) Overview(ctx context.Context) (*Overview, error) {
	o := &Overview{
		Contents:  ContentStats{ByStatus: map[string]int{}, ByType: map[string]int{}},
		Collected: CollectedStats{ByStatus: map[string]int{}},
		FlowRuns:  FlowRunStats{ByStatus: map[string]int{}},
		Projects:  ProjectStats{ByStatus: map[string]int{}},
		Notes:     NoteStats{ByType: map[string]int{}},
		Activity:  ActivityStats{BySource: map[string]int{}},
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return s.queryContentStats(ctx, &o.Contents) })
	g.Go(func() error { return s.queryCollectedStats(ctx, &o.Collected) })
	g.Go(func() error { return s.queryFeedStats(ctx, &o.Feeds) })
	g.Go(func() error { return s.queryFlowRunStats(ctx, &o.FlowRuns) })
	g.Go(func() error { return s.queryProjectStats(ctx, &o.Projects) })
	g.Go(func() error { return s.queryReviewStats(ctx, &o.Reviews) })
	g.Go(func() error { return s.queryNoteStats(ctx, &o.Notes) })
	g.Go(func() error { return s.queryActivityStats(ctx, &o.Activity) })
	g.Go(func() error { return s.querySourceStats(ctx, &o.Sources) })
	g.Go(func() error { return s.queryTagStats(ctx, &o.Tags) })

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

func (s *Store) queryFlowRunStats(ctx context.Context, fs *FlowRunStats) error {
	rows, err := s.q.StatsFlowRunsByStatus(ctx)
	if err != nil {
		return fmt.Errorf("flow_runs stats: %w", err)
	}
	for i := range rows {
		count := int(rows[i].Count)
		fs.Total += count
		fs.ByStatus[rows[i].Status] += count
	}
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

func (s *Store) queryReviewStats(ctx context.Context, rs *ReviewStats) error {
	row, err := s.q.StatsEditorialQueueCounts(ctx)
	if err != nil {
		return fmt.Errorf("editorial_queue stats: %w", err)
	}
	rs.Total = int(row.Total)
	rs.Pending = int(row.Pending)
	return nil
}

func (s *Store) queryNoteStats(ctx context.Context, ns *NoteStats) error {
	rows, err := s.q.StatsNotesByType(ctx)
	if err != nil {
		return fmt.Errorf("notes stats: %w", err)
	}
	for i := range rows {
		count := int(rows[i].Count)
		ns.Total += count
		ns.ByType[rows[i].Type] += count
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

func (s *Store) querySourceStats(ctx context.Context, ss *SourceStats) error {
	row, err := s.q.StatsSyncSourceCounts(ctx)
	if err != nil {
		return fmt.Errorf("sync_sources stats: %w", err)
	}
	ss.Total = int(row.Total)
	ss.Enabled = int(row.Enabled)
	return nil
}

func (s *Store) queryTagStats(ctx context.Context, ts *TagStats) error {
	row, err := s.q.StatsTagCounts(ctx)
	if err != nil {
		return fmt.Errorf("tag stats: %w", err)
	}
	ts.Canonical = int(row.Canonical)
	ts.Aliases = int(row.Aliases)
	ts.Unconfirmed = int(row.Unconfirmed)
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

// FlowRunsSince returns flow run counts by status since the given time,
// optionally filtered by flow name and status.
func (s *Store) FlowRunsSince(ctx context.Context, since time.Time, flowName, status *string) (*FlowStatusSummary, error) {
	row, err := s.q.StatsFlowRunsSummary(ctx, db.StatsFlowRunsSummaryParams{
		Since:    since,
		FlowName: flowName,
		Status:   nullFlowStatus(status),
	})
	if err != nil {
		return nil, fmt.Errorf("querying flow run stats since %v: %w", since, err)
	}
	return &FlowStatusSummary{
		Total:     int(row.Total),
		Completed: int(row.Completed),
		Failed:    int(row.Failed),
		Running:   int(row.Running),
	}, nil
}

// nullFlowStatus converts an optional status string to db.NullFlowStatus.
// Used by FlowRunsSince and RecentFlowRuns to convert handler-level
// optional filters into the sqlc-generated nullable enum type.
func nullFlowStatus(s *string) db.NullFlowStatus {
	if s == nil {
		return db.NullFlowStatus{}
	}
	return db.NullFlowStatus{FlowStatus: db.FlowStatus(*s), Valid: true}
}

// FeedHealth returns feed health summary including failing feed count.
func (s *Store) FeedHealth(ctx context.Context) (*FeedHealthSummary, error) {
	row, err := s.q.StatsFeedHealthSummary(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying feed health: %w", err)
	}
	return &FeedHealthSummary{
		Total:        int(row.Total),
		Enabled:      int(row.Enabled),
		FailingFeeds: int(row.FailingFeeds),
	}, nil
}

// RecentFlowRuns returns recent flow runs within a time window,
// optionally filtered by flow name and status.
func (s *Store) RecentFlowRuns(ctx context.Context, since time.Time, flowName, status *string, limit int) ([]RecentFlowRun, error) {
	rows, err := s.q.StatsRecentFlowRuns(ctx, db.StatsRecentFlowRunsParams{
		Since:      since,
		FlowName:   flowName,
		Status:     nullFlowStatus(status),
		MaxResults: int32(limit), // #nosec G115 -- bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("querying recent flow runs: %w", err)
	}
	runs := make([]RecentFlowRun, 0, len(rows))
	for i := range rows {
		r := RecentFlowRun{
			ID:        rows[i].ID.String(),
			FlowName:  rows[i].FlowName,
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

// PipelineSummaries returns per-flow-name aggregated stats within a time window.
func (s *Store) PipelineSummaries(ctx context.Context, since time.Time) ([]PipelineSummary, error) {
	rows, err := s.q.StatsPipelineSummaries(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("querying pipeline summaries: %w", err)
	}
	summaries := make([]PipelineSummary, 0, len(rows))
	for i := range rows {
		ps := PipelineSummary{
			FlowName:  rows[i].FlowName,
			Total:     int(rows[i].Total),
			Completed: int(rows[i].Completed),
			Failed:    int(rows[i].Failed),
			Running:   int(rows[i].Running),
		}
		if str, ok := rows[i].LastStatus.(string); ok && str != "" {
			ps.LastStatus = &str
		}
		if t, ok := rows[i].LastRunAt.(time.Time); ok && !t.IsZero() {
			s := t.Format(time.RFC3339)
			ps.LastRunAt = &s
		}
		summaries = append(summaries, ps)
	}
	return summaries, nil
}

// Learning returns aggregated learning metrics for the admin dashboard.
func (s *Store) Learning(ctx context.Context) (*LearningDashboard, error) {
	ld := &LearningDashboard{
		Notes:    NoteGrowth{ByType: map[string]int{}},
		Activity: WeeklyActivity{Trend: "stable"},
		TopTags:  []TagCount{},
	}

	// Each section is independent — partial failures return zeros so the
	// tool always returns a response even when some tables are empty.
	var hasData bool

	if err := s.learningNoteGrowth(ctx, ld); err != nil {
		slog.Warn("learning: note growth query failed, returning zeros", "error", err)
	} else {
		hasData = true
	}

	if err := s.learningWeeklyActivity(ctx, ld); err != nil {
		slog.Warn("learning: weekly activity query failed, returning zeros", "error", err)
	} else {
		hasData = true
	}

	if err := s.learningTopTags(ctx, ld); err != nil {
		slog.Warn("learning: top tags query failed, returning zeros", "error", err)
	} else {
		hasData = true
	}

	if !hasData {
		return nil, fmt.Errorf("all learning queries failed: check database connectivity and migration status")
	}

	return ld, nil
}

func (s *Store) learningNoteGrowth(ctx context.Context, ld *LearningDashboard) error {
	row, err := s.q.StatsNoteGrowth(ctx)
	if err != nil {
		return fmt.Errorf("note growth: %w", err)
	}
	ld.Notes.Total = int(row.Total)
	ld.Notes.LastWeek = int(row.LastWeek)
	ld.Notes.LastMonth = int(row.LastMonth)

	rows, err := s.q.StatsNoteGrowthByType(ctx)
	if err != nil {
		return fmt.Errorf("notes by type: %w", err)
	}
	for i := range rows {
		ld.Notes.ByType[rows[i].Type] = int(rows[i].Count)
	}
	return nil
}

func (s *Store) learningWeeklyActivity(ctx context.Context, ld *LearningDashboard) error {
	row, err := s.q.StatsWeeklyActivity(ctx)
	if err != nil {
		return fmt.Errorf("weekly activity: %w", err)
	}
	ld.Activity.ThisWeek = int(row.ThisWeek)
	ld.Activity.LastWeek = int(row.LastWeek)

	switch {
	case ld.Activity.ThisWeek > ld.Activity.LastWeek:
		ld.Activity.Trend = "up"
	case ld.Activity.ThisWeek < ld.Activity.LastWeek:
		ld.Activity.Trend = "down"
	default:
		ld.Activity.Trend = "stable"
	}
	return nil
}

func (s *Store) learningTopTags(ctx context.Context, ld *LearningDashboard) error {
	rows, err := s.q.StatsTopTags(ctx)
	if err != nil {
		return fmt.Errorf("top tags: %w", err)
	}
	for i := range rows {
		ld.TopTags = append(ld.TopTags, TagCount{
			Name:  rows[i].Name,
			Count: int(rows[i].Count),
		})
	}
	return nil
}

// SystemHealth returns the snapshot consumed by the admin SystemHealthComponent.
//
// Composes feed health, recent pipeline activity (last 24h), and core entity
// counts. AI budget tracking is not yet implemented — those fields return
// zero placeholders so the frontend contract holds.
func (s *Store) SystemHealth(ctx context.Context) (*SystemHealthSnapshot, error) {
	out := &SystemHealthSnapshot{
		Feeds:     FeedHealth{FailingFeeds: []FailingFeed{}},
		Pipelines: PipelineHealth{},
		AIBudget:  AIBudget{},
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
	pipeline, err := s.q.StatsPipelineActivityRecent(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("querying pipeline activity: %w", err)
	}
	out.Pipelines.RecentRuns = int(pipeline.RecentRuns)
	out.Pipelines.Failed = int(pipeline.Failed)
	if t, ok := pipeline.LastRunAt.(time.Time); ok && !t.IsZero() {
		s := t.Format(time.RFC3339)
		out.Pipelines.LastRunAt = &s
	}

	dbCounts, err := s.q.StatsDatabaseCounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying database counts: %w", err)
	}
	out.Database.ContentsCount = int(dbCounts.ContentsCount)
	out.Database.TasksCount = int(dbCounts.TodosCount)
	out.Database.NotesCount = int(dbCounts.NotesCount)

	return out, nil
}
