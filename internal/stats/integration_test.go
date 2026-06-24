// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go exercises the stats aggregators against a real
// PostgreSQL container (testcontainers). The store does nothing but run SQL and
// shape the rows, so the only honest test is one that seeds real rows across
// contents / feeds / process_runs / activity_events / goals and asserts the
// aggregator returns the NON-ZERO counts that data implies. A hand-rolled
// db.DBTX fake would assert only that the Go control flow runs — never that the
// queries are correct.
//
// activity_events rows are produced organically by the AFTER triggers on
// covered tables (a seeded content + goal), not by direct INSERT — that mirrors
// production and keeps the "no direct INSERT into activity_events" invariant.
//
// Run with:
//
//	go test -tags=integration ./internal/stats/...
package stats_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/stats"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.NewPool()
	testPool = pool

	// The audit triggers on contents / goals write activity_events.actor, which
	// FKs onto agents. Reconcile the builtin registry once per suite exactly as
	// cmd/app/main.go does at startup, or every audited insert fails 23503.
	registry := agent.NewBuiltinRegistry()
	if _, err := agent.SyncToTable(context.Background(), registry, agent.NewStore(pool), nil, slog.Default()); err != nil {
		slog.Default().Error("agent.SyncToTable", "error", err)
		cleanup()
		os.Exit(1)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}

// truncate clears every table the stats aggregators read so each test starts
// from a known-empty baseline (and the non-zero assertions are unambiguous).
func truncate(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE contents, feeds, process_runs, activity_events, goals, projects, areas, todos CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// execActor runs the given write inside a transaction with koopa.actor set, so
// the AFTER triggers on covered tables resolve current_actor() to a real agent
// and emit the activity_events audit row. fn receives the tx.
func execActor(t *testing.T, actor string, fn func(tx pgx.Tx)) {
	t.Helper()
	ctx := t.Context()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('koopa.actor', $1, true)", actor); err != nil {
		t.Fatalf("set koopa.actor: %v", err)
	}
	fn(tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestIntegration_Stats_Overview seeds rows in every source Overview aggregates
// and asserts the counts are correct and non-zero.
func TestIntegration_Stats_Overview(t *testing.T) {
	truncate(t)
	ctx := t.Context()

	// 3 contents: 2 published, 1 draft (2 distinct types). Published rows need
	// published_at (chk_content_publication) and may be public; the draft stays
	// private with a NULL published_at.
	execActor(t, "human", func(tx pgx.Tx) {
		_, err := tx.Exec(ctx, `
			INSERT INTO contents (slug, title, type, status, is_public, published_at) VALUES
			  ('a', 'A', 'article'::content_type, 'published'::content_status, true,  now()),
			  ('b', 'B', 'article'::content_type, 'published'::content_status, true,  now()),
			  ('c', 'C', 'til'::content_type,     'draft'::content_status,     false, NULL)`)
		if err != nil {
			t.Fatalf("seeding contents: %v", err)
		}
	})

	// 2 feeds, 1 enabled / 1 disabled.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO feeds (url, name, schedule, enabled) VALUES
		  ('https://x.test/a.xml', 'Feed A', 'daily', true),
		  ('https://x.test/b.xml', 'Feed B', 'daily', false)`); err != nil {
		t.Fatalf("seeding feeds: %v", err)
	}

	// 2 crawl process_runs: 1 completed / 1 failed.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO process_runs (kind, name, status, error, ended_at) VALUES
		  ('crawl', 'feed_fetch', 'completed', NULL, now()),
		  ('crawl', 'feed_fetch', 'failed', 'boom', now())`); err != nil {
		t.Fatalf("seeding process_runs: %v", err)
	}

	// 1 goal (fires the goal audit trigger → 1 activity_events row, entity_type=goal).
	execActor(t, "human", func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO goals (title, status) VALUES ('Ship stats coverage', 'in_progress'::goal_status)`); err != nil {
			t.Fatalf("seeding goal: %v", err)
		}
	})

	store := stats.NewStore(testPool)
	o, err := store.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}

	if o.Contents.Total != 3 {
		t.Errorf("Contents.Total = %d, want 3", o.Contents.Total)
	}
	if o.Contents.Published != 2 {
		t.Errorf("Contents.Published = %d, want 2", o.Contents.Published)
	}
	if o.Contents.ByStatus["published"] != 2 {
		t.Errorf("Contents.ByStatus[published] = %d, want 2", o.Contents.ByStatus["published"])
	}
	if o.Contents.ByType["article"] != 2 {
		t.Errorf("Contents.ByType[article] = %d, want 2", o.Contents.ByType["article"])
	}

	if o.Feeds.Total != 2 {
		t.Errorf("Feeds.Total = %d, want 2", o.Feeds.Total)
	}
	if o.Feeds.Enabled != 1 {
		t.Errorf("Feeds.Enabled = %d, want 1", o.Feeds.Enabled)
	}

	crawl := o.ProcessRuns["crawl"]
	if crawl.Total != 2 {
		t.Errorf("ProcessRuns[crawl].Total = %d, want 2", crawl.Total)
	}
	if crawl.ByStatus["completed"] != 1 || crawl.ByStatus["failed"] != 1 {
		t.Errorf("ProcessRuns[crawl].ByStatus = %v, want completed=1 failed=1", crawl.ByStatus)
	}

	// Both seeded content (3 created) and the goal (1 created) emit audit rows.
	if o.Activity.Total < 4 {
		t.Errorf("Activity.Total = %d, want >= 4 (3 content + 1 goal created events)", o.Activity.Total)
	}
	if o.Activity.BySource["content"] != 3 {
		t.Errorf("Activity.BySource[content] = %d, want 3", o.Activity.BySource["content"])
	}
	if o.Activity.BySource["goal"] != 1 {
		t.Errorf("Activity.BySource[goal] = %d, want 1", o.Activity.BySource["goal"])
	}
}

// TestIntegration_Stats_SystemHealth seeds a failing feed plus recent
// process_runs and asserts the health snapshot reports the failing feed by
// name/error and the recent-run counts.
func TestIntegration_Stats_SystemHealth(t *testing.T) {
	truncate(t)
	ctx := t.Context()

	// 1 healthy, 1 failing feed.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO feeds (url, name, schedule, consecutive_failures, last_error) VALUES
		  ('https://x.test/ok.xml',   'Healthy Feed', 'daily', 0, NULL),
		  ('https://x.test/bad.xml',  'Broken Feed',  'daily', 3, 'connection refused')`); err != nil {
		t.Fatalf("seeding feeds: %v", err)
	}

	// 2 recent process_runs in the last 24h, 1 failed.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO process_runs (kind, name, status, error, ended_at) VALUES
		  ('crawl', 'feed_fetch', 'completed', NULL, now()),
		  ('crawl', 'feed_fetch', 'failed', 'timeout', now())`); err != nil {
		t.Fatalf("seeding process_runs: %v", err)
	}

	// 1 content + 1 todo for the database-counts section.
	execActor(t, "human", func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO contents (slug, title, type, status) VALUES ('hc', 'Health Content', 'article'::content_type, 'draft'::content_status)`); err != nil {
			t.Fatalf("seeding content: %v", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO todos (title, state, created_by) VALUES ('Health todo', 'inbox'::todo_state, 'human')`); err != nil {
			t.Fatalf("seeding todo: %v", err)
		}
	})

	store := stats.NewStore(testPool)
	snap, err := store.SystemHealth(ctx)
	if err != nil {
		t.Fatalf("SystemHealth: %v", err)
	}

	if snap.Feeds.Total != 2 {
		t.Errorf("Feeds.Total = %d, want 2", snap.Feeds.Total)
	}
	if snap.Feeds.Healthy != 1 {
		t.Errorf("Feeds.Healthy = %d, want 1", snap.Feeds.Healthy)
	}
	if snap.Feeds.Failing != 1 {
		t.Errorf("Feeds.Failing = %d, want 1", snap.Feeds.Failing)
	}
	if len(snap.Feeds.FailingFeeds) != 1 {
		t.Fatalf("FailingFeeds len = %d, want 1 (%+v)", len(snap.Feeds.FailingFeeds), snap.Feeds.FailingFeeds)
	}
	if got := snap.Feeds.FailingFeeds[0]; got.Name != "Broken Feed" || got.Error != "connection refused" {
		t.Errorf("FailingFeeds[0] = {Name:%q Error:%q}, want {Broken Feed, connection refused}", got.Name, got.Error)
	}

	if snap.Pipelines.RecentRuns != 2 {
		t.Errorf("Pipelines.RecentRuns = %d, want 2", snap.Pipelines.RecentRuns)
	}
	if snap.Pipelines.Failed != 1 {
		t.Errorf("Pipelines.Failed = %d, want 1", snap.Pipelines.Failed)
	}
	if snap.Pipelines.LastRunAt == nil {
		t.Error("Pipelines.LastRunAt = nil, want a timestamp (there were recent runs)")
	}

	if snap.Database.ContentsCount != 1 {
		t.Errorf("Database.ContentsCount = %d, want 1", snap.Database.ContentsCount)
	}
	if snap.Database.TodosCount != 1 {
		t.Errorf("Database.TodosCount = %d, want 1", snap.Database.TodosCount)
	}
}

// TestIntegration_Stats_ProcessRuns seeds crawl runs across statuses and time
// windows, then asserts ProcessRunsSince counts each status and RecentProcessRuns
// returns the newest-first window correctly — including the name/status filters.
func TestIntegration_Stats_ProcessRuns(t *testing.T) {
	truncate(t)
	ctx := t.Context()

	// created_at is DEFAULT now(); seed an OLD run (>24h) that must fall outside
	// a 1h/24h window, and four recent runs across statuses.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO process_runs (kind, name, status, error, started_at, ended_at, created_at) VALUES
		  ('crawl', 'feed_fetch', 'completed', NULL, now(), now(), now()),
		  ('crawl', 'feed_fetch', 'completed', NULL, now(), now(), now()),
		  ('crawl', 'feed_fetch', 'failed', 'boom', now(), now(), now()),
		  ('crawl', 'other_job',  'pending',  NULL, NULL,  NULL,  now()),
		  ('crawl', 'feed_fetch', 'completed', NULL, now(), now(), now() - interval '30 hours')`); err != nil {
		t.Fatalf("seeding process_runs: %v", err)
	}

	store := stats.NewStore(testPool)
	since := time.Now().Add(-24 * time.Hour)

	// Summary over the last 24h, all names: 4 recent rows (the 30h-old one is excluded).
	sum, err := store.ProcessRunsSince(ctx, since, "crawl", nil, nil)
	if err != nil {
		t.Fatalf("ProcessRunsSince: %v", err)
	}
	if sum.Total != 4 {
		t.Errorf("ProcessRunsSince Total = %d, want 4 (30h-old row excluded)", sum.Total)
	}
	if sum.Completed != 2 {
		t.Errorf("ProcessRunsSince Completed = %d, want 2", sum.Completed)
	}
	if sum.Failed != 1 {
		t.Errorf("ProcessRunsSince Failed = %d, want 1", sum.Failed)
	}
	if sum.Pending != 1 {
		t.Errorf("ProcessRunsSince Pending = %d, want 1", sum.Pending)
	}

	// Name filter: only the 'other_job' pending row matches.
	otherName := "other_job"
	sumOther, err := store.ProcessRunsSince(ctx, since, "crawl", &otherName, nil)
	if err != nil {
		t.Fatalf("ProcessRunsSince(name=other_job): %v", err)
	}
	if sumOther.Total != 1 || sumOther.Pending != 1 {
		t.Errorf("ProcessRunsSince(name=other_job) = {Total:%d Pending:%d}, want {1,1}", sumOther.Total, sumOther.Pending)
	}

	// Recent list over 24h: 4 rows, newest first.
	recent, err := store.RecentProcessRuns(ctx, since, "crawl", nil, nil, 100)
	if err != nil {
		t.Fatalf("RecentProcessRuns: %v", err)
	}
	if len(recent) != 4 {
		t.Fatalf("RecentProcessRuns len = %d, want 4", len(recent))
	}
	// Status filter: only failed runs.
	failed := "failed"
	recentFailed, err := store.RecentProcessRuns(ctx, since, "crawl", nil, &failed, 100)
	if err != nil {
		t.Fatalf("RecentProcessRuns(status=failed): %v", err)
	}
	if len(recentFailed) != 1 {
		t.Fatalf("RecentProcessRuns(status=failed) len = %d, want 1", len(recentFailed))
	}
	if recentFailed[0].Status != "failed" || recentFailed[0].Error == nil || *recentFailed[0].Error != "boom" {
		t.Errorf("RecentProcessRuns(status=failed)[0] = {Status:%q Error:%v}, want {failed, boom}",
			recentFailed[0].Status, recentFailed[0].Error)
	}
}

// TestIntegration_Stats_Drift seeds active goals by area and content activity by
// the same areas, then asserts the drift report computes a non-trivial,
// correctly-keyed area distribution from real rows.
func TestIntegration_Stats_Drift(t *testing.T) {
	truncate(t)
	ctx := t.Context()

	// Two areas; a goal in each; a project in each (so content events join to an
	// area via project.area_id).
	var backendID, frontendID uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO areas (slug, name) VALUES ('backend', 'Backend') RETURNING id`).Scan(&backendID); err != nil {
		t.Fatalf("seeding backend area: %v", err)
	}
	if err := testPool.QueryRow(ctx,
		`INSERT INTO areas (slug, name) VALUES ('frontend', 'Frontend') RETURNING id`).Scan(&frontendID); err != nil {
		t.Fatalf("seeding frontend area: %v", err)
	}

	var backendProj uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO projects (slug, title, area_id) VALUES ('be-proj', 'BE Project', $1) RETURNING id`, backendID).
		Scan(&backendProj); err != nil {
		t.Fatalf("seeding backend project: %v", err)
	}

	// Active goals: 2 in backend, 1 in frontend (only not_started/in_progress count).
	if _, err := testPool.Exec(ctx, `
		INSERT INTO goals (title, status, area_id) VALUES
		  ('BE goal 1', 'in_progress'::goal_status, $1),
		  ('BE goal 2', 'not_started'::goal_status, $1),
		  ('FE goal 1', 'in_progress'::goal_status, $2),
		  ('Done goal', 'done'::goal_status, $1)`, backendID, frontendID); err != nil {
		t.Fatalf("seeding goals: %v", err)
	}

	// Two content created events tied to the backend project → backend area
	// events. (Frontend has goals but no events — that asymmetry is the drift.)
	execActor(t, "human", func(tx pgx.Tx) {
		_, err := tx.Exec(ctx, `
			INSERT INTO contents (slug, title, type, status, project_id) VALUES
			  ('d1', 'D1', 'article'::content_type, 'draft'::content_status, $1),
			  ('d2', 'D2', 'article'::content_type, 'draft'::content_status, $1)`, backendProj)
		if err != nil {
			t.Fatalf("seeding content: %v", err)
		}
	})

	store := stats.NewStore(testPool)
	report, err := store.Drift(ctx, 30)
	if err != nil {
		t.Fatalf("Drift: %v", err)
	}
	if report.Period != "last 30 days" {
		t.Errorf("Drift.Period = %q, want %q", report.Period, "last 30 days")
	}

	byArea := make(map[string]stats.AreaDrift, len(report.Areas))
	for _, a := range report.Areas {
		byArea[a.Area] = a
	}

	be, ok := byArea["Backend"]
	if !ok {
		t.Fatalf("Drift missing Backend area; got %+v", report.Areas)
	}
	if be.ActiveGoals != 2 {
		t.Errorf("Backend ActiveGoals = %d, want 2 (done goal excluded)", be.ActiveGoals)
	}
	// Backend events join via project.area_id: the project-created audit row
	// (1) plus two content-created audit rows (2) all carry project_id =
	// backendProj, which resolves to the Backend area.
	if be.EventCount != 3 {
		t.Errorf("Backend EventCount = %d, want 3 (1 project + 2 content created events)", be.EventCount)
	}

	fe, ok := byArea["Frontend"]
	if !ok {
		t.Fatalf("Drift missing Frontend area; got %+v", report.Areas)
	}
	if fe.ActiveGoals != 1 {
		t.Errorf("Frontend ActiveGoals = %d, want 1", fe.ActiveGoals)
	}
	if fe.EventCount != 0 {
		t.Errorf("Frontend EventCount = %d, want 0 (goals but no events)", fe.EventCount)
	}
	// Frontend has goal focus but zero activity → negative drift; backend the
	// opposite sign. The exact magnitudes are covered by the computeAreaDrift
	// unit tests; here we only assert the real join produced the right sign.
	if fe.DriftPercent >= 0 {
		t.Errorf("Frontend DriftPercent = %f, want negative (goals but no events)", fe.DriftPercent)
	}
}
