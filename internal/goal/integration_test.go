// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles the testcontainers-backed admin handler tests
// for the goal package (W8 admin-surface coverage). Every mutation handler is
// driven through api.ActorMiddleware via httptest — never store.Mutation on a
// bare pool — because the goals/milestones audit triggers read koopa.actor
// from the per-request transaction the middleware binds, and the production
// admin route (cmd/app/routes.go adminMid) always wires that tx.
//
// Coverage:
//   - Create — POST /api/admin/commitment/goals → 201, goal persisted in
//     status=not_started.
//   - CreateMilestone — POST /goals/{id}/milestones → 201, milestone persisted
//     under the parent goal.
//   - UpdateStatus on a non-existent goal → 404. This guards the #6 fix:
//     UpdateStatus now routes the store ErrNotFound through api.HandleError /
//     storeErrors instead of leaking a 500.
//
// Run with:
//
//	go test -tags=integration ./internal/goal/...
package goal_test

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
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// goals / milestones audit triggers write activity_events.actor, which
	// FKs onto agents. Reconcile the builtin registry once per suite exactly
	// as cmd/app/main.go does at startup, or every audited insert fails 23503.
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

// truncate clears every table the goal handlers touch so each test starts
// clean. activity_events is wiped too — the audit rows would otherwise leak
// across cases.
func truncate(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE milestones, goals, activity_events CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// newHandler wires a goal.Handler against the shared test pool. The project
// store is nil because none of the mutation handlers under test (Create,
// CreateMilestone, UpdateStatus) dereference it — only Detail does, and Detail
// is not exercised here.
func newHandler() *goal.Handler {
	return goal.NewHandler(goal.NewStore(testPool), nil, slog.Default())
}

// serve runs an admin request through ActorMiddleware (actor="human", the
// admin-write convention) into the given handler, mirroring the production
// adminMid chain. Returns the recorder so the caller can assert status + body.
func serve(t *testing.T, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	mid := api.ActorMiddleware(testPool, "human", slog.Default())
	wrapped := mid(h)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	return rec
}

// postJSON builds a POST request with a JSON body and the admin content type.
func postJSON(t *testing.T, target string, body any) *http.Request {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// decodeID extracts data.id from an api.Response envelope.
func decodeID(t *testing.T, body []byte) uuid.UUID {
	t.Helper()
	var env struct {
		Data struct {
			ID uuid.UUID `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, body)
	}
	if env.Data.ID == uuid.Nil {
		t.Fatalf("response missing id: %s", body)
	}
	return env.Data.ID
}

// TestIntegration_Goal_Create drives POST /api/admin/commitment/goals through
// the middleware and asserts the goal lands in the DB in status=not_started
// with actor=human on its audit row.
func TestIntegration_Goal_Create(t *testing.T) {
	truncate(t)
	h := newHandler()

	req := postJSON(t, "/api/admin/commitment/goals", map[string]any{
		"title":       "Pass JLPT N2 by December",
		"description": "Structured Japanese study toward N2.",
	})
	rec := serve(t, h.Create, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", resp.StatusCode, body)
	}

	id := decodeID(t, body)

	// Persistence + invariant: the row exists and the store-enforced create
	// status is not_started, regardless of any status passed in the body.
	var title, status string
	if err := testPool.QueryRow(t.Context(),
		`SELECT title, status FROM goals WHERE id = $1`, id,
	).Scan(&title, &status); err != nil {
		t.Fatalf("reading created goal %s: %v", id, err)
	}
	if title != "Pass JLPT N2 by December" {
		t.Errorf("title = %q, want %q", title, "Pass JLPT N2 by December")
	}
	if status != string(goal.StatusNotStarted) {
		t.Errorf("status = %q, want %q (create always lands not_started)", status, goal.StatusNotStarted)
	}

	// Audit provenance: the tx-bound koopa.actor must have reached the trigger.
	var actor string
	if err := testPool.QueryRow(t.Context(),
		`SELECT actor FROM activity_events WHERE entity_type = 'goal' AND entity_id = $1
		 ORDER BY occurred_at DESC LIMIT 1`, id,
	).Scan(&actor); err != nil {
		t.Fatalf("reading goal audit row: %v", err)
	}
	if actor != "human" {
		t.Errorf("activity_events.actor = %q, want %q (tx-in-context did not propagate)", actor, "human")
	}
}

// TestIntegration_Goal_CreateMilestone seeds a goal, then drives
// POST /goals/{id}/milestones twice and asserts both milestones persist with
// appended positions (0, then 1). The second insert is the regression guard:
// the insert used to omit position, so every milestone landed on the DEFAULT 0
// and the second one died on UNIQUE(goal_id, position).
func TestIntegration_Goal_CreateMilestone(t *testing.T) {
	truncate(t)
	h := newHandler()

	// Seed the parent goal directly — the milestone FK needs an existing
	// goal_id, and this test is scoped to the milestone create path.
	var goalID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title, status) VALUES ('Parent Goal', 'in_progress') RETURNING id`,
	).Scan(&goalID); err != nil {
		t.Fatalf("seeding goal: %v", err)
	}

	req := postJSON(t, "/api/admin/commitment/goals/"+goalID.String()+"/milestones", map[string]any{
		"title":       "Finish Genki I",
		"description": "All chapters + exercises.",
	})
	req.SetPathValue("id", goalID.String())
	rec := serve(t, h.CreateMilestone, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", resp.StatusCode, body)
	}

	id := decodeID(t, body)

	var gotGoalID uuid.UUID
	var gotTitle string
	var gotPosition int32
	if err := testPool.QueryRow(t.Context(),
		`SELECT goal_id, title, position FROM milestones WHERE id = $1`, id,
	).Scan(&gotGoalID, &gotTitle, &gotPosition); err != nil {
		t.Fatalf("reading created milestone %s: %v", id, err)
	}
	if gotGoalID != goalID {
		t.Errorf("milestone goal_id = %s, want %s", gotGoalID, goalID)
	}
	if gotTitle != "Finish Genki I" {
		t.Errorf("milestone title = %q, want %q", gotTitle, "Finish Genki I")
	}
	if gotPosition != 0 {
		t.Errorf("first milestone position = %d, want 0", gotPosition)
	}

	req2 := postJSON(t, "/api/admin/commitment/goals/"+goalID.String()+"/milestones", map[string]any{
		"title": "Finish Genki II",
	})
	req2.SetPathValue("id", goalID.String())
	rec2 := serve(t, h.CreateMilestone, req2)

	resp2 := rec2.Result()
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)

	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("second milestone status = %d, want 201 (body=%s)", resp2.StatusCode, body2)
	}

	id2 := decodeID(t, body2)
	var gotPosition2 int32
	if err := testPool.QueryRow(t.Context(),
		`SELECT position FROM milestones WHERE id = $1`, id2,
	).Scan(&gotPosition2); err != nil {
		t.Fatalf("reading second milestone %s: %v", id2, err)
	}
	if gotPosition2 != 1 {
		t.Errorf("second milestone position = %d, want 1 (append after existing max)", gotPosition2)
	}
}

// TestIntegration_Goal_List_StatusFilter seeds goals in two statuses and
// asserts GET /goals?status=in_progress returns only the in_progress goal.
func TestIntegration_Goal_List_StatusFilter(t *testing.T) {
	truncate(t)
	h := newHandler()

	var active, dream uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title, status) VALUES ('Active Goal', 'in_progress') RETURNING id`,
	).Scan(&active); err != nil {
		t.Fatalf("seeding in_progress goal: %v", err)
	}
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title, status) VALUES ('Dream Goal', 'not_started') RETURNING id`,
	).Scan(&dream); err != nil {
		t.Fatalf("seeding not_started goal: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/goals?status=in_progress", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	var env struct {
		Data []struct {
			ID     uuid.UUID `json:"id"`
			Status string    `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode list response: %v (body=%s)", err, body)
	}
	if len(env.Data) != 1 {
		t.Fatalf("filtered list returned %d goals, want 1 (body=%s)", len(env.Data), body)
	}
	if env.Data[0].ID != active {
		t.Errorf("filtered goal id = %s, want %s (the in_progress goal)", env.Data[0].ID, active)
	}
	if env.Data[0].Status != "in_progress" {
		t.Errorf("filtered goal status = %q, want %q", env.Data[0].Status, "in_progress")
	}
}

// TestIntegration_Goal_ToggleMilestone seeds an incomplete milestone, toggles
// it (asserting completed_at becomes non-NULL), then toggles again (asserting
// it clears back to NULL).
func TestIntegration_Goal_ToggleMilestone(t *testing.T) {
	truncate(t)
	h := newHandler()

	var goalID, milestoneID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title, status) VALUES ('Goal With Milestone', 'in_progress') RETURNING id`,
	).Scan(&goalID); err != nil {
		t.Fatalf("seeding goal: %v", err)
	}
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO milestones (goal_id, title) VALUES ($1, 'Finish chapter 1') RETURNING id`,
		goalID,
	).Scan(&milestoneID); err != nil {
		t.Fatalf("seeding milestone: %v", err)
	}

	toggle := func() *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost,
			"/api/admin/commitment/goals/"+goalID.String()+"/milestones/"+milestoneID.String()+"/toggle", nil)
		req.SetPathValue("id", goalID.String())
		req.SetPathValue("mid", milestoneID.String())
		return serve(t, h.ToggleMilestone, req)
	}

	// First toggle: completed_at should flip from NULL to non-NULL.
	rec := toggle()
	if rec.Code != http.StatusOK {
		t.Fatalf("first toggle status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var completedAt *time.Time
	if err := testPool.QueryRow(t.Context(),
		`SELECT completed_at FROM milestones WHERE id = $1`, milestoneID,
	).Scan(&completedAt); err != nil {
		t.Fatalf("reading milestone after first toggle: %v", err)
	}
	if completedAt == nil {
		t.Error("completed_at is NULL after first toggle, want non-NULL")
	}

	// Second toggle: completed_at should clear back to NULL.
	rec = toggle()
	if rec.Code != http.StatusOK {
		t.Fatalf("second toggle status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if err := testPool.QueryRow(t.Context(),
		`SELECT completed_at FROM milestones WHERE id = $1`, milestoneID,
	).Scan(&completedAt); err != nil {
		t.Fatalf("reading milestone after second toggle: %v", err)
	}
	if completedAt != nil {
		t.Errorf("completed_at = %v after second toggle, want NULL", completedAt)
	}
}

// TestIntegration_Goal_UpdateStatus_NotFound guards the #6 fix: UpdateStatus
// on a goal id that does not exist must produce a 404 (store ErrNotFound routed
// through api.HandleError / storeErrors), not a 500. A bare uuid that parses
// but matches no row is the exact regression case.
func TestIntegration_Goal_UpdateStatus_NotFound(t *testing.T) {
	truncate(t)
	h := newHandler()

	missing := uuid.New()
	req := postJSON(t, "/api/admin/commitment/goals/"+missing.String()+"/status", map[string]any{
		"status": "in_progress",
	})
	// PUT in production; the handler does not branch on method, and the path
	// value is what matters. Set it explicitly the way the mux would.
	req.Method = http.MethodPut
	req.SetPathValue("id", missing.String())
	rec := serve(t, h.UpdateStatus, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for unknown goal (body=%s)", resp.StatusCode, body)
	}

	// The body must carry the structured NOT_FOUND code, confirming the
	// sentinel was mapped rather than a generic 500 leaking.
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode error envelope: %v (body=%s)", err, body)
	}
	if env.Error.Code != "NOT_FOUND" {
		t.Errorf("error.code = %q, want %q", env.Error.Code, "NOT_FOUND")
	}
}
