package stats

// Raw SQL is required here: stats aggregation spans 11 tables across different
// feature packages. sqlc cannot express cross-table COUNT aggregation efficiently,
// and creating per-table sqlc queries would duplicate the logic already in each
// feature's own query.sql. Parameters are passed via pgx placeholders ($1), no
// string interpolation of user input.

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store aggregates stats from all platform tables.
type Store struct {
	dbtx db.DBTX
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{dbtx: dbtx}
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
	rows, err := s.dbtx.Query(ctx, `SELECT status::text, type::text, COUNT(*) FROM contents GROUP BY status, type`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var status, ctype string
		var count int
		if err := rows.Scan(&status, &ctype, &count); err != nil {
			return err
		}
		cs.Total += count
		cs.ByStatus[status] += count
		cs.ByType[ctype] += count
		if status == "published" {
			cs.Published += count
		}
	}
	return rows.Err()
}

func (s *Store) queryCollectedStats(ctx context.Context, cs *CollectedStats) error {
	rows, err := s.dbtx.Query(ctx, `SELECT status::text, COUNT(*) FROM collected_data GROUP BY status`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return err
		}
		cs.Total += count
		cs.ByStatus[status] += count
	}
	return rows.Err()
}

func (s *Store) queryFeedStats(ctx context.Context, fs *FeedStats) error {
	return s.dbtx.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE enabled) FROM feeds`,
	).Scan(&fs.Total, &fs.Enabled)
}

func (s *Store) queryFlowRunStats(ctx context.Context, fs *FlowRunStats) error {
	rows, err := s.dbtx.Query(ctx, `SELECT status::text, COUNT(*) FROM flow_runs GROUP BY status`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return err
		}
		fs.Total += count
		fs.ByStatus[status] += count
	}
	return rows.Err()
}

func (s *Store) queryProjectStats(ctx context.Context, ps *ProjectStats) error {
	rows, err := s.dbtx.Query(ctx, `SELECT status::text, COUNT(*) FROM projects GROUP BY status`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return err
		}
		ps.Total += count
		ps.ByStatus[status] += count
	}
	return rows.Err()
}

func (s *Store) queryReviewStats(ctx context.Context, rs *ReviewStats) error {
	return s.dbtx.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE status = 'pending') FROM review_queue`,
	).Scan(&rs.Total, &rs.Pending)
}

func (s *Store) queryNoteStats(ctx context.Context, ns *NoteStats) error {
	rows, err := s.dbtx.Query(ctx, `SELECT COALESCE(type, 'unknown'), COUNT(*) FROM obsidian_notes GROUP BY type`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var ntype string
		var count int
		if err := rows.Scan(&ntype, &count); err != nil {
			return err
		}
		ns.Total += count
		ns.ByType[ntype] += count
	}
	return rows.Err()
}

func (s *Store) queryActivityStats(ctx context.Context, as *ActivityStats) error {
	err := s.dbtx.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE timestamp > now() - interval '24 hours'),
			COUNT(*) FILTER (WHERE timestamp > now() - interval '7 days')
		FROM activity_events`,
	).Scan(&as.Total, &as.Last24h, &as.Last7d)
	if err != nil {
		return err
	}

	rows, err := s.dbtx.Query(ctx, `SELECT source, COUNT(*) FROM activity_events GROUP BY source`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var source string
		var count int
		if err := rows.Scan(&source, &count); err != nil {
			return err
		}
		as.BySource[source] += count
	}
	return rows.Err()
}

func (s *Store) querySourceStats(ctx context.Context, ss *SourceStats) error {
	return s.dbtx.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE enabled) FROM notion_sources`,
	).Scan(&ss.Total, &ss.Enabled)
}

func (s *Store) queryTagStats(ctx context.Context, ts *TagStats) error {
	return s.dbtx.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM tags),
			(SELECT COUNT(*) FROM tag_aliases),
			(SELECT COUNT(*) FROM tag_aliases WHERE NOT confirmed)`,
	).Scan(&ts.Canonical, &ts.Aliases, &ts.Unconfirmed)
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

func (s *Store) queryGoalsByArea(ctx context.Context) (map[string]int, int, error) { //nolint:gocritic // named results conflict with local := declarations
	rows, err := s.dbtx.Query(ctx, `
		SELECT COALESCE(area, 'unset'), COUNT(*)
		FROM goals WHERE status IN ('not-started', 'in-progress')
		GROUP BY area`)
	if err != nil {
		return nil, 0, fmt.Errorf("querying goals by area: %w", err)
	}
	defer rows.Close()

	byArea := map[string]int{}
	total := 0
	for rows.Next() {
		var area string
		var count int
		if err := rows.Scan(&area, &count); err != nil {
			return nil, 0, err
		}
		byArea[area] = count
		total += count
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return byArea, total, nil
}

func (s *Store) queryEventsByArea(ctx context.Context, days int) (map[string]int, int, error) { //nolint:gocritic // named results conflict with local := declarations
	rows, err := s.dbtx.Query(ctx, `
		SELECT COALESCE(p.area, 'unset'), COUNT(*)
		FROM activity_events ae
		LEFT JOIN projects p ON ae.project = p.slug OR (p.repo IS NOT NULL AND p.repo != '' AND ae.project = p.repo)
		WHERE ae.timestamp > now() - make_interval(days => $1)
		GROUP BY p.area`, days)
	if err != nil {
		return nil, 0, fmt.Errorf("querying events by area: %w", err)
	}
	defer rows.Close()

	byArea := map[string]int{}
	total := 0
	for rows.Next() {
		var area string
		var count int
		if err := rows.Scan(&area, &count); err != nil {
			return nil, 0, err
		}
		byArea[area] = count
		total += count
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
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
	row := s.dbtx.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'completed'),
			COUNT(*) FILTER (WHERE status = 'failed'),
			COUNT(*) FILTER (WHERE status = 'running')
		FROM flow_runs
		WHERE created_at >= $1
			AND ($2::text IS NULL OR flow_name = $2)
			AND ($3::flow_status IS NULL OR status = $3::flow_status)`,
		since, flowName, status)

	var fs FlowStatusSummary
	if err := row.Scan(&fs.Total, &fs.Completed, &fs.Failed, &fs.Running); err != nil {
		return nil, fmt.Errorf("querying flow run stats since %v: %w", since, err)
	}
	return &fs, nil
}

// FeedHealth returns feed health summary including failing feed count.
func (s *Store) FeedHealth(ctx context.Context) (*FeedHealthSummary, error) {
	row := s.dbtx.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE enabled),
			COUNT(*) FILTER (WHERE consecutive_failures > 0)
		FROM feeds`)

	var fh FeedHealthSummary
	if err := row.Scan(&fh.Total, &fh.Enabled, &fh.FailingFeeds); err != nil {
		return nil, fmt.Errorf("querying feed health: %w", err)
	}
	return &fh, nil
}

// RecentFlowRuns returns recent flow runs within a time window,
// optionally filtered by flow name and status.
func (s *Store) RecentFlowRuns(ctx context.Context, since time.Time, flowName, status *string, limit int) ([]RecentFlowRun, error) {
	rows, err := s.dbtx.Query(ctx, `
		SELECT id, flow_name, status::text, error, created_at, ended_at
		FROM flow_runs
		WHERE created_at >= $1
			AND ($2::text IS NULL OR flow_name = $2)
			AND ($3::flow_status IS NULL OR status = $3::flow_status)
		ORDER BY created_at DESC
		LIMIT $4`,
		since, flowName, status, limit)
	if err != nil {
		return nil, fmt.Errorf("querying recent flow runs: %w", err)
	}
	defer rows.Close()

	var runs []RecentFlowRun
	for rows.Next() {
		var r RecentFlowRun
		var id uuid.UUID
		var createdAt time.Time
		var endedAt *time.Time
		if err := rows.Scan(&id, &r.FlowName, &r.Status, &r.Error, &createdAt, &endedAt); err != nil {
			return nil, err
		}
		r.ID = id.String()
		r.CreatedAt = createdAt.Format(time.RFC3339)
		if endedAt != nil {
			s := endedAt.Format(time.RFC3339)
			r.EndedAt = &s
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if runs == nil {
		runs = []RecentFlowRun{}
	}
	return runs, nil
}

// PipelineSummaries returns per-flow-name aggregated stats within a time window.
func (s *Store) PipelineSummaries(ctx context.Context, since time.Time) ([]PipelineSummary, error) {
	rows, err := s.dbtx.Query(ctx, `
		SELECT
			flow_name,
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'completed'),
			COUNT(*) FILTER (WHERE status = 'failed'),
			COUNT(*) FILTER (WHERE status = 'running'),
			MAX(created_at),
			(array_agg(status::text ORDER BY created_at DESC))[1]
		FROM flow_runs
		WHERE created_at >= $1
		GROUP BY flow_name
		ORDER BY flow_name`,
		since)
	if err != nil {
		return nil, fmt.Errorf("querying pipeline summaries: %w", err)
	}
	defer rows.Close()

	var summaries []PipelineSummary
	for rows.Next() {
		var ps PipelineSummary
		var lastRunAt *time.Time
		if err := rows.Scan(&ps.FlowName, &ps.Total, &ps.Completed, &ps.Failed, &ps.Running, &lastRunAt, &ps.LastStatus); err != nil {
			return nil, err
		}
		if lastRunAt != nil {
			s := lastRunAt.Format(time.RFC3339)
			ps.LastRunAt = &s
		}
		summaries = append(summaries, ps)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if summaries == nil {
		summaries = []PipelineSummary{}
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
	// tool always returns a response even when some tables are empty or
	// missing (e.g. obsidian sync not yet configured).
	var hasData bool

	// Note growth (obsidian_notes + contents TIL entries)
	if err := s.learningNoteGrowth(ctx, ld); err != nil {
		slog.Warn("learning: note growth query failed, returning zeros", "error", err)
	} else {
		hasData = true
	}

	// Weekly activity comparison (activity_events)
	if err := s.learningWeeklyActivity(ctx, ld); err != nil {
		slog.Warn("learning: weekly activity query failed, returning zeros", "error", err)
	} else {
		hasData = true
	}

	// Top tags by count (obsidian_note_tags + contents TIL tags)
	if err := s.learningTopTags(ctx, ld); err != nil {
		slog.Warn("learning: top tags query failed, returning zeros", "error", err)
	} else {
		hasData = true
	}

	// If none of the queries succeeded, report the error — likely a
	// database connectivity issue rather than empty tables.
	if !hasData {
		return nil, fmt.Errorf("all learning queries failed: check database connectivity and migration status")
	}

	return ld, nil
}

func (s *Store) learningNoteGrowth(ctx context.Context, ld *LearningDashboard) error {
	// Aggregate from BOTH obsidian_notes AND contents (TIL entries).
	// obsidian_notes uses synced_at; contents uses created_at.
	err := s.dbtx.QueryRow(ctx, `
		SELECT
			COALESCE(o.total, 0) + COALESCE(c.total, 0),
			COALESCE(o.last_week, 0) + COALESCE(c.last_week, 0),
			COALESCE(o.last_month, 0) + COALESCE(c.last_month, 0)
		FROM
			(SELECT COUNT(*) AS total,
				COUNT(*) FILTER (WHERE synced_at > now() - interval '7 days') AS last_week,
				COUNT(*) FILTER (WHERE synced_at > now() - interval '30 days') AS last_month
			 FROM obsidian_notes) o,
			(SELECT COUNT(*) AS total,
				COUNT(*) FILTER (WHERE created_at > now() - interval '7 days') AS last_week,
				COUNT(*) FILTER (WHERE created_at > now() - interval '30 days') AS last_month
			 FROM contents WHERE type = 'til') c
	`).Scan(&ld.Notes.Total, &ld.Notes.LastWeek, &ld.Notes.LastMonth)
	if err != nil {
		return fmt.Errorf("note growth: %w", err)
	}

	// By-type breakdown: obsidian_notes types + TIL count from contents.
	noteRows, err := s.dbtx.Query(ctx, `
		SELECT type, SUM(cnt)::int FROM (
			SELECT COALESCE(type, 'unknown') AS type, COUNT(*) AS cnt FROM obsidian_notes GROUP BY type
			UNION ALL
			SELECT 'til' AS type, COUNT(*) AS cnt FROM contents WHERE type = 'til'
		) combined
		GROUP BY type`)
	if err != nil {
		return fmt.Errorf("notes by type: %w", err)
	}
	defer noteRows.Close()
	for noteRows.Next() {
		var ntype string
		var count int
		if scanErr := noteRows.Scan(&ntype, &count); scanErr != nil {
			return scanErr
		}
		ld.Notes.ByType[ntype] = count
	}
	return noteRows.Err()
}

func (s *Store) learningWeeklyActivity(ctx context.Context, ld *LearningDashboard) error {
	err := s.dbtx.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE timestamp > now() - interval '7 days'),
			COUNT(*) FILTER (WHERE timestamp > now() - interval '14 days' AND timestamp <= now() - interval '7 days')
		FROM activity_events`).Scan(&ld.Activity.ThisWeek, &ld.Activity.LastWeek)
	if err != nil {
		return fmt.Errorf("weekly activity: %w", err)
	}

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
	// Aggregate tags from BOTH obsidian_note_tags junction AND contents.tags TEXT[].
	tagRows, err := s.dbtx.Query(ctx, `
		SELECT name, SUM(cnt)::int AS total FROM (
			SELECT t.name, COUNT(ont.note_id) AS cnt
			FROM tags t
			JOIN obsidian_note_tags ont ON ont.tag_id = t.id
			GROUP BY t.id, t.name
			UNION ALL
			SELECT UNNEST(tags) AS name, COUNT(*) AS cnt
			FROM contents
			WHERE type = 'til' AND tags != '{}'
			GROUP BY UNNEST(tags)
		) combined
		GROUP BY name
		ORDER BY total DESC
		LIMIT 10`)
	if err != nil {
		return fmt.Errorf("top tags: %w", err)
	}
	defer tagRows.Close()
	for tagRows.Next() {
		var tc TagCount
		if scanErr := tagRows.Scan(&tc.Name, &tc.Count); scanErr != nil {
			return scanErr
		}
		ld.TopTags = append(ld.TopTags, tc)
	}
	return tagRows.Err()
}
