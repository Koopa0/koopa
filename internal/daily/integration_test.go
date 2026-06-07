// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles the testcontainers-backed admin handler tests
// for the daily plan-write path (PUT /api/admin/commitment/daily-plan — the
// human equivalent of the MCP plan_day tool). The handler is driven through
// api.ActorMiddleware via httptest, never on a bare pool: PutPlan extracts the
// per-request tx and rebinds both the daily and todo stores to it so the
// delete-then-insert and todo-state validations commit atomically, and the
// daily_plan_items audit trigger reads koopa.actor from that tx. The production
// admin route (cmd/app/routes.go adminMid) always binds it.
//
// Coverage:
//   - PutPlan happy path — sets a plan; items persist in the requested order.
//   - empty items → 400.
//   - inbox-state todo → 400 (must be clarified to state=todo first).
//   - out-of-range position → 400.
//
// Run with:
//
//	go test -tags=integration ./internal/daily/...
package daily_test

import (
	"bytes"
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
	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/testdb"
	"github.com/Koopa0/koopa/internal/todo"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// daily_plan_items.selected_by + the audit trigger's actor FK onto agents.
	// Reconcile the builtin registry once per suite, same as cmd/app/main.go.
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

// truncate clears the daily plan + todo tables (and the audit log) so each
// test starts clean.
func truncate(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE daily_plan_items, todos, activity_events CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// newHandler wires a daily.Handler with a real todo store against the shared
// test pool — the plan-write path needs both.
func newHandler() *daily.Handler {
	return daily.NewHandler(daily.NewStore(testPool), todo.NewStore(testPool), slog.Default())
}

// serve runs an admin request through ActorMiddleware (actor="human") into the
// handler, mirroring the production adminMid chain that binds the tx PutPlan
// requires.
func serve(t *testing.T, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	mid := api.ActorMiddleware(testPool, "human", slog.Default())
	wrapped := mid(h)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	return rec
}

// putJSON builds a PUT request with a JSON body and the admin content type.
func putJSON(t *testing.T, target string, body any) *http.Request {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, target, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// seedTodo inserts a todo in the given state and returns its id.
func seedTodo(t *testing.T, title, state string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state, created_by) VALUES ($1, $2, 'human') RETURNING id`,
		title, state,
	).Scan(&id); err != nil {
		t.Fatalf("seeding todo %q: %v", title, err)
	}
	return id
}

// errorCode extracts error.code from an api.ErrorBody envelope.
func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode error envelope: %v (body=%s)", err, body)
	}
	return env.Error.Code
}

// TestIntegration_Daily_PutPlan_HappyPath drives PUT /daily-plan with two
// state=todo items (no explicit dates) and asserts they persist in the
// requested order under today's plan.
func TestIntegration_Daily_PutPlan_HappyPath(t *testing.T) {
	truncate(t)
	h := newHandler()

	first := seedTodo(t, "Write the API", "todo")
	second := seedTodo(t, "Review the PR", "todo")

	req := putJSON(t, "/api/admin/commitment/daily-plan", map[string]any{
		"items": []map[string]any{
			{"todo_id": first.String()},
			{"todo_id": second.String()},
		},
	})
	rec := serve(t, h.PutPlan, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	// Both todos must be planned, and the positions must follow request order.
	type row struct {
		todoID   uuid.UUID
		position int32
	}
	rows, err := testPool.Query(t.Context(),
		`SELECT todo_id, position FROM daily_plan_items WHERE plan_date = CURRENT_DATE ORDER BY position`,
	)
	if err != nil {
		t.Fatalf("reading plan rows: %v", err)
	}
	defer rows.Close()
	var got []row
	for rows.Next() {
		var rrow row
		if err := rows.Scan(&rrow.todoID, &rrow.position); err != nil {
			t.Fatalf("scanning plan row: %v", err)
		}
		got = append(got, rrow)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating plan rows: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("plan row count = %d, want 2", len(got))
	}
	if got[0].todoID != first {
		t.Errorf("position-0 todo = %s, want %s (request order)", got[0].todoID, first)
	}
	if got[1].todoID != second {
		t.Errorf("position-1 todo = %s, want %s (request order)", got[1].todoID, second)
	}

	// Provenance: daily_plan_items has no audit trigger; the actor flows to
	// selected_by instead. It must be the middleware's "human", confirming the
	// tx-bound caller identity reached the write.
	var selectedBy string
	if err := testPool.QueryRow(t.Context(),
		`SELECT selected_by FROM daily_plan_items WHERE plan_date = CURRENT_DATE LIMIT 1`,
	).Scan(&selectedBy); err != nil {
		t.Fatalf("reading selected_by: %v", err)
	}
	if selectedBy != "human" {
		t.Errorf("daily_plan_items.selected_by = %q, want %q", selectedBy, "human")
	}
}

// TestIntegration_Daily_PutPlan_EmptyItems asserts an empty items list is
// rejected with 400 before any write.
func TestIntegration_Daily_PutPlan_EmptyItems(t *testing.T) {
	truncate(t)
	h := newHandler()

	req := putJSON(t, "/api/admin/commitment/daily-plan", map[string]any{
		"items": []map[string]any{},
	})
	rec := serve(t, h.PutPlan, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for empty items (body=%s)", resp.StatusCode, body)
	}
	if code := errorCode(t, body); code != "BAD_REQUEST" {
		t.Errorf("error.code = %q, want %q", code, "BAD_REQUEST")
	}
}

// TestIntegration_Daily_PutPlan_InboxRejected asserts that planning a todo
// still in inbox state is rejected with 400, mirroring plan_day. The previous
// plan (if any) must be left intact.
func TestIntegration_Daily_PutPlan_InboxRejected(t *testing.T) {
	truncate(t)
	h := newHandler()

	inbox := seedTodo(t, "Unclarified capture", "inbox")

	req := putJSON(t, "/api/admin/commitment/daily-plan", map[string]any{
		"items": []map[string]any{
			{"todo_id": inbox.String()},
		},
	})
	rec := serve(t, h.PutPlan, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for inbox-state todo (body=%s)", resp.StatusCode, body)
	}

	// Atomicity: nothing must have been planned.
	var count int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM daily_plan_items WHERE plan_date = CURRENT_DATE`,
	).Scan(&count); err != nil {
		t.Fatalf("counting plan rows: %v", err)
	}
	if count != 0 {
		t.Errorf("plan row count = %d, want 0 (inbox rejection must precede any commit)", count)
	}
}

// TestIntegration_Daily_PutPlan_PositionOutOfRange asserts an out-of-bounds
// position is rejected with 400 before any write.
func TestIntegration_Daily_PutPlan_PositionOutOfRange(t *testing.T) {
	truncate(t)
	h := newHandler()

	todoID := seedTodo(t, "Valid todo", "todo")

	req := putJSON(t, "/api/admin/commitment/daily-plan", map[string]any{
		"items": []map[string]any{
			{"todo_id": todoID.String(), "position": 100001},
		},
	})
	rec := serve(t, h.PutPlan, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for out-of-range position (body=%s)", resp.StatusCode, body)
	}

	var count int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM daily_plan_items WHERE plan_date = CURRENT_DATE`,
	).Scan(&count); err != nil {
		t.Fatalf("counting plan rows: %v", err)
	}
	if count != 0 {
		t.Errorf("plan row count = %d, want 0 (bounds rejection must precede any write)", count)
	}
}
