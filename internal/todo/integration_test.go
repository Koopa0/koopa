// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles the testcontainers-backed admin handler tests
// for the todo recurring + history read views. These are read-only handlers
// (authMid in production) so they need no per-request tx; they run directly
// against the shared pool-bound store.
//
// Coverage:
//   - Recurring — seed a recurring todo due today and an overdue one; assert
//     each lands in the right bucket.
//   - History — seed a completed todo; assert it appears in the default
//     completed-since view.
//
// Run with:
//
//	go test -tags=integration ./internal/todo/...
package todo_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/testdb"
	"github.com/Koopa0/koopa/internal/todo"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// todos.created_by FKs onto agents. Reconcile the builtin registry once
	// per suite, same as cmd/app/main.go at startup.
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

// truncate clears the todos table (and the audit log) so each test starts
// clean.
func truncate(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE todos, activity_events CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// newHandler wires a todo.Handler against the shared test pool.
func newHandler() *todo.Handler {
	return todo.NewHandler(todo.NewStore(testPool), slog.Default())
}

// serveRead runs a read request directly into the handler (no middleware —
// these are authMid read handlers that need no tx).
func serveRead(t *testing.T, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// dataIDs extracts the set of data[].id values from an api.Response list
// envelope.
func dataIDs(t *testing.T, body []byte) map[uuid.UUID]struct{} {
	t.Helper()
	var env struct {
		Data []struct {
			ID uuid.UUID `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, body)
	}
	out := make(map[uuid.UUID]struct{}, len(env.Data))
	for _, d := range env.Data {
		out[d.ID] = struct{}{}
	}
	return out
}

// TestIntegration_Todo_Recurring seeds a recurring todo due today and a
// recurring todo overdue, then asserts the handler buckets each correctly.
func TestIntegration_Todo_Recurring(t *testing.T) {
	truncate(t)
	h := newHandler()

	var dueToday, overdue uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state, due, recur_interval, recur_unit, created_by)
		 VALUES ('Daily standup', 'todo', CURRENT_DATE, 1, 'days', 'human') RETURNING id`,
	).Scan(&dueToday); err != nil {
		t.Fatalf("seeding due-today recurring todo: %v", err)
	}
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state, due, recur_interval, recur_unit, created_by)
		 VALUES ('Weekly review', 'todo', CURRENT_DATE - 3, 1, 'weeks', 'human') RETURNING id`,
	).Scan(&overdue); err != nil {
		t.Fatalf("seeding overdue recurring todo: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/todos/recurring", nil)
	rec := serveRead(t, h.Recurring, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	var env struct {
		Data struct {
			DueToday []struct {
				ID uuid.UUID `json:"id"`
			} `json:"due_today"`
			Overdue []struct {
				ID uuid.UUID `json:"id"`
			} `json:"overdue"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode recurring response: %v (body=%s)", err, body)
	}

	dueIDs := make(map[uuid.UUID]struct{}, len(env.Data.DueToday))
	for _, d := range env.Data.DueToday {
		dueIDs[d.ID] = struct{}{}
	}
	overdueIDs := make(map[uuid.UUID]struct{}, len(env.Data.Overdue))
	for _, d := range env.Data.Overdue {
		overdueIDs[d.ID] = struct{}{}
	}

	if _, ok := dueIDs[dueToday]; !ok {
		t.Errorf("due-today recurring todo %s missing from due_today bucket (body=%s)", dueToday, body)
	}
	if _, ok := overdueIDs[overdue]; !ok {
		t.Errorf("overdue recurring todo %s missing from overdue bucket (body=%s)", overdue, body)
	}
}

// TestIntegration_Todo_History seeds a completed todo and asserts it appears
// in the default (completed-since) history view.
func TestIntegration_Todo_History(t *testing.T) {
	truncate(t)
	h := newHandler()

	var done uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state, completed_at, created_by)
		 VALUES ('Shipped the feature', 'done', now(), 'human') RETURNING id`,
	).Scan(&done); err != nil {
		t.Fatalf("seeding completed todo: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/todos/history", nil)
	rec := serveRead(t, h.History, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	ids := dataIDs(t, body)
	if _, ok := ids[done]; !ok {
		t.Errorf("completed todo %s missing from history (body=%s)", done, body)
	}
}
