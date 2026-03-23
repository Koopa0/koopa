package stats

// Raw SQL is required here: stats aggregation spans 11 tables across different
// feature packages. sqlc cannot express cross-table COUNT aggregation efficiently,
// and creating per-table sqlc queries would duplicate the logic already in each
// feature's own query.sql. Parameters are passed via pgx placeholders ($1), no
// string interpolation of user input.

import (
	"context"
	"fmt"
	"slices"

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
func (s *Store) Overview(ctx context.Context) (*Overview, error) {
	o := &Overview{
		Contents:  ContentStats{ByStatus: map[string]int{}, ByType: map[string]int{}},
		Collected: CollectedStats{ByStatus: map[string]int{}},
		FlowRuns:  FlowRunStats{ByStatus: map[string]int{}},
		Projects:  ProjectStats{ByStatus: map[string]int{}},
		Notes:     NoteStats{ByType: map[string]int{}},
		Activity:  ActivityStats{BySource: map[string]int{}},
	}

	if err := s.queryContentStats(ctx, &o.Contents); err != nil {
		return nil, fmt.Errorf("content stats: %w", err)
	}
	if err := s.queryCollectedStats(ctx, &o.Collected); err != nil {
		return nil, fmt.Errorf("collected stats: %w", err)
	}
	if err := s.queryFeedStats(ctx, &o.Feeds); err != nil {
		return nil, fmt.Errorf("feed stats: %w", err)
	}
	if err := s.queryFlowRunStats(ctx, &o.FlowRuns); err != nil {
		return nil, fmt.Errorf("flow run stats: %w", err)
	}
	if err := s.queryProjectStats(ctx, &o.Projects); err != nil {
		return nil, fmt.Errorf("project stats: %w", err)
	}
	if err := s.queryReviewStats(ctx, &o.Reviews); err != nil {
		return nil, fmt.Errorf("review stats: %w", err)
	}
	if err := s.queryNoteStats(ctx, &o.Notes); err != nil {
		return nil, fmt.Errorf("note stats: %w", err)
	}
	if err := s.queryActivityStats(ctx, &o.Activity); err != nil {
		return nil, fmt.Errorf("activity stats: %w", err)
	}
	if err := s.querySourceStats(ctx, &o.Sources); err != nil {
		return nil, fmt.Errorf("source stats: %w", err)
	}
	if err := s.queryTagStats(ctx, &o.Tags); err != nil {
		return nil, fmt.Errorf("tag stats: %w", err)
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

// Learning returns aggregated learning metrics for the admin dashboard.
func (s *Store) Learning(ctx context.Context) (*LearningDashboard, error) {
	ld := &LearningDashboard{
		Notes: NoteGrowth{ByType: map[string]int{}},
	}

	// Note growth
	err := s.dbtx.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE synced_at > now() - interval '7 days'),
			COUNT(*) FILTER (WHERE synced_at > now() - interval '30 days')
		FROM obsidian_notes`).Scan(&ld.Notes.Total, &ld.Notes.LastWeek, &ld.Notes.LastMonth)
	if err != nil {
		return nil, fmt.Errorf("note growth: %w", err)
	}

	noteRows, err := s.dbtx.Query(ctx, `SELECT COALESCE(type, 'unknown'), COUNT(*) FROM obsidian_notes GROUP BY type`)
	if err != nil {
		return nil, fmt.Errorf("notes by type: %w", err)
	}
	defer noteRows.Close()
	for noteRows.Next() {
		var ntype string
		var count int
		if scanErr := noteRows.Scan(&ntype, &count); scanErr != nil {
			return nil, scanErr
		}
		ld.Notes.ByType[ntype] = count
	}
	if rowsErr := noteRows.Err(); rowsErr != nil {
		return nil, rowsErr
	}

	// Weekly activity comparison
	err = s.dbtx.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE timestamp > now() - interval '7 days'),
			COUNT(*) FILTER (WHERE timestamp > now() - interval '14 days' AND timestamp <= now() - interval '7 days')
		FROM activity_events`).Scan(&ld.Activity.ThisWeek, &ld.Activity.LastWeek)
	if err != nil {
		return nil, fmt.Errorf("weekly activity: %w", err)
	}

	switch {
	case ld.Activity.ThisWeek > ld.Activity.LastWeek:
		ld.Activity.Trend = "up"
	case ld.Activity.ThisWeek < ld.Activity.LastWeek:
		ld.Activity.Trend = "down"
	default:
		ld.Activity.Trend = "stable"
	}

	// Top tags by note count
	tagRows, err := s.dbtx.Query(ctx, `
		SELECT t.name, COUNT(ont.note_id) AS cnt
		FROM tags t
		JOIN obsidian_note_tags ont ON ont.tag_id = t.id
		GROUP BY t.id, t.name
		ORDER BY cnt DESC
		LIMIT 10`)
	if err != nil {
		return nil, fmt.Errorf("top tags: %w", err)
	}
	defer tagRows.Close()
	for tagRows.Next() {
		var tc TagCount
		if err := tagRows.Scan(&tc.Name, &tc.Count); err != nil {
			return nil, err
		}
		ld.TopTags = append(ld.TopTags, tc)
	}
	if err := tagRows.Err(); err != nil {
		return nil, err
	}
	if ld.TopTags == nil {
		ld.TopTags = []TagCount{}
	}

	return ld, nil
}
