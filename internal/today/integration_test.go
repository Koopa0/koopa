// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go drives GET /api/admin/commitment/today against a real
// PostgreSQL (testcontainers), proving the Today aggregate — the HTTP mirror
// of brief(mode=morning) — populates its contracted sections from the live
// domain stores and that empty sections marshal as [] (never null).
//
// Coverage:
//   - seeded todo (due today) + goal (in_progress) populate their sections.
//   - empty database returns every list as [].
//
// Run with:
//
//	go test -count=1 -tags=integration ./internal/today/...
package today_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/feed/entry"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/testdb"
	"github.com/Koopa0/koopa/internal/today"
	"github.com/Koopa0/koopa/internal/todo"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.NewPool()
	testPool = pool

	// created_by / domain FKs reference the agents + builtin registry rows.
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

// truncate clears every table the Today aggregate reads so each test starts
// clean. CASCADE handles the FK chains (plan → todos).
func truncate(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE daily_plan_items, todos, goals, activity_events CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// newHandler wires the today.Handler to the real stores against the shared
// test pool — exactly the wiring cmd/app/main.go installs.
func newHandler() *today.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return today.NewHandler(daily.NewStore(testPool), time.UTC, logger).WithSources(
		todo.NewStore(testPool),
		goal.NewStore(testPool),
		entry.NewStore(testPool),
	)
}

func getToday(t *testing.T, h *today.Handler) (*httptest.ResponseRecorder, today.Response) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/today", http.NoBody)
	rec := httptest.NewRecorder()
	h.Today(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Data today.Response `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	return rec, body.Data
}

// TestIntegration_Today_SectionsPopulate seeds one row per contracted source
// and asserts each section carries it.
func TestIntegration_Today_SectionsPopulate(t *testing.T) {
	truncate(t)
	ctx := t.Context()
	h := newHandler()

	// todo due today → today_todos
	if _, err := testPool.Exec(ctx,
		`INSERT INTO todos (title, state, due, created_by)
		 VALUES ('review the PR', 'todo', CURRENT_DATE, 'human')`,
	); err != nil {
		t.Fatalf("seed todo: %v", err)
	}

	// goal in_progress → active_goals
	if _, err := testPool.Exec(ctx,
		`INSERT INTO goals (title, status) VALUES ('GDE application', 'in_progress')`,
	); err != nil {
		t.Fatalf("seed goal: %v", err)
	}

	_, got := getToday(t, h)

	if len(got.TodayTodos) != 1 || got.TodayTodos[0].Title != "review the PR" {
		t.Errorf("today_todos = %+v, want one 'review the PR'", got.TodayTodos)
	}
	if len(got.ActiveGoals) != 1 || got.ActiveGoals[0].Title != "GDE application" {
		t.Errorf("active_goals = %+v, want one 'GDE application'", got.ActiveGoals)
	}
}

// TestIntegration_Today_EmptyStateArrays asserts an empty database yields []
// for every list section.
func TestIntegration_Today_EmptyStateArrays(t *testing.T) {
	truncate(t)
	h := newHandler()

	rec, got := getToday(t, h)

	for _, tc := range []struct {
		name string
		n    int
	}{
		{"overdue_todos", len(got.OverdueTodos)},
		{"today_todos", len(got.TodayTodos)},
		{"committed_todos", len(got.CommittedTodos)},
		{"upcoming_todos", len(got.UpcomingTodos)},
		{"active_goals", len(got.ActiveGoals)},
		{"rss_highlights", len(got.RSSHighlights)},
	} {
		if tc.n != 0 {
			t.Errorf("%s len = %d, want 0", tc.name, tc.n)
		}
	}

	// Wire-level: no list field may serialize as null.
	raw := rec.Body.String()
	for _, field := range []string{
		"overdue_todos", "today_todos", "committed_todos", "upcoming_todos",
		"active_goals", "rss_highlights",
	} {
		if strings.Contains(raw, `"`+field+`":null`) {
			t.Errorf("field %q serialized as null, want []", field)
		}
	}
}
