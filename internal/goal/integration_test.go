// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles the testcontainers-backed admin handler tests
// for the goal package. Every mutation handler is driven through
// api.ActorMiddleware via httptest — never store.Mutation on a bare
// pool — because the goals/milestones audit triggers read koopa.actor
// from the per-request transaction the middleware binds, and the production
// admin route (cmd/app/routes.go adminMid) always wires that tx.
//
// Coverage:
//   - Create — POST /api/admin/commitment/goals → 201, goal persisted in
//     status=not_started.
//   - CreateMilestone — POST /goals/{id}/milestones → 201, milestone persisted
//     under the parent goal.
//   - UpdateStatus on a non-existent goal → 404. This guards the regression
//     where the store ErrNotFound leaked as a 500 instead of routing through
//     api.HandleError / storeErrors.
//   - Update — PUT /goals/{id} partial update (provided fields change,
//     omitted fields survive) + 404 for an unknown goal.
//   - UpdateMilestone / DeleteMilestone — membership-bound {id, mid}
//     mutations; a goal/milestone mismatch is a 404, never a cross-goal
//     write.
//   - ListAreas — GET /areas returns the migration-seeded PARA rows.
//
// Run with:
//
//	go test -tags=integration ./internal/goal/...
package goal_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/Koopa0/koopa/internal/project"
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
// CreateMilestone, UpdateStatus) dereference it — only Detail and the
// project-aware triage reads do, and those are not exercised here.
func newHandler() *goal.Handler {
	return goal.NewHandler(goal.NewStore(testPool), nil, slog.Default())
}

// newHandlerWithProjects wires a goal.Handler with a real project store so the
// proposals triage (Proposals / ProposalsCount) can read proposed projects —
// the project component the goal store cannot see.
func newHandlerWithProjects() *goal.Handler {
	return goal.NewHandler(goal.NewStore(testPool), project.NewStore(testPool), slog.Default())
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

// TestIntegration_Goal_UpdateStatus_NotFound guards the 404 contract:
// UpdateStatus on a goal id that does not exist must produce a 404 (store
// ErrNotFound routed through api.HandleError / storeErrors), not a 500. A bare
// uuid that parses but matches no row is the exact regression case.
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

// putJSON builds a PUT request with a JSON body and the admin content type.
func putJSON(t *testing.T, target string, body any) *http.Request {
	t.Helper()
	req := postJSON(t, target, body)
	req.Method = http.MethodPut
	return req
}

// errCode extracts error.code from an api error envelope.
func errCode(t *testing.T, body []byte) string {
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

// seedGoal inserts a goal row and returns its id.
func seedGoal(t *testing.T, title string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title, description, status) VALUES ($1, 'original description', 'in_progress') RETURNING id`,
		title,
	).Scan(&id); err != nil {
		t.Fatalf("seeding goal %q: %v", title, err)
	}
	return id
}

// seedMilestone inserts a milestone under the given goal and returns its id.
func seedMilestone(t *testing.T, goalID uuid.UUID, title string, position int32) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO milestones (goal_id, title, position) VALUES ($1, $2, $3) RETURNING id`,
		goalID, title, position,
	).Scan(&id); err != nil {
		t.Fatalf("seeding milestone %q: %v", title, err)
	}
	return id
}

// TestIntegration_Goal_Update drives PUT /goals/{id} through the middleware:
// provided fields change, omitted fields survive, and an unknown goal is a
// 404.
func TestIntegration_Goal_Update(t *testing.T) {
	truncate(t)
	h := newHandler()

	id := seedGoal(t, "Original title")

	// Resolve a real area so the partial update can also rewire area_id.
	var areaID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`SELECT id FROM areas WHERE slug = 'learning'`,
	).Scan(&areaID); err != nil {
		t.Fatalf("resolving seeded area: %v", err)
	}

	req := putJSON(t, "/api/admin/commitment/goals/"+id.String(), map[string]any{
		"title":   "Updated title",
		"quarter": "2026-Q3",
		"area_id": areaID,
	})
	req.SetPathValue("id", id.String())
	rec := serve(t, h.Update, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	var title, description, quarter string
	var gotArea *uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`SELECT title, description, COALESCE(quarter, ''), area_id FROM goals WHERE id = $1`, id,
	).Scan(&title, &description, &quarter, &gotArea); err != nil {
		t.Fatalf("reading updated goal: %v", err)
	}
	if title != "Updated title" {
		t.Errorf("title = %q, want %q", title, "Updated title")
	}
	if description != "original description" {
		t.Errorf("description = %q, want %q (omitted field must survive)", description, "original description")
	}
	if quarter != "2026-Q3" {
		t.Errorf("quarter = %q, want %q", quarter, "2026-Q3")
	}
	if gotArea == nil || *gotArea != areaID {
		t.Errorf("area_id = %v, want %s", gotArea, areaID)
	}

	// Unknown goal → 404 NOT_FOUND.
	missing := uuid.New()
	req404 := putJSON(t, "/api/admin/commitment/goals/"+missing.String(), map[string]any{
		"title": "Whatever",
	})
	req404.SetPathValue("id", missing.String())
	rec404 := serve(t, h.Update, req404)

	resp404 := rec404.Result()
	defer resp404.Body.Close()
	body404, _ := io.ReadAll(resp404.Body)

	if resp404.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for unknown goal (body=%s)", resp404.StatusCode, body404)
	}
	if code := errCode(t, body404); code != "NOT_FOUND" {
		t.Errorf("error.code = %q, want %q", code, "NOT_FOUND")
	}
}

// TestIntegration_Goal_UpdateMilestone drives PUT /goals/{id}/milestones/{mid}
// through the middleware: a partial title update lands, and a {goal, mid}
// membership mismatch is a 404 with the row untouched.
func TestIntegration_Goal_UpdateMilestone(t *testing.T) {
	truncate(t)
	h := newHandler()

	goalID := seedGoal(t, "Goal A")
	otherGoalID := seedGoal(t, "Goal B")
	mid := seedMilestone(t, goalID, "Original milestone", 0)

	req := putJSON(t,
		"/api/admin/commitment/goals/"+goalID.String()+"/milestones/"+mid.String(),
		map[string]any{"title": "Renamed milestone"})
	req.SetPathValue("id", goalID.String())
	req.SetPathValue("mid", mid.String())
	rec := serve(t, h.UpdateMilestone, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	var title string
	if err := testPool.QueryRow(t.Context(),
		`SELECT title FROM milestones WHERE id = $1`, mid,
	).Scan(&title); err != nil {
		t.Fatalf("reading updated milestone: %v", err)
	}
	if title != "Renamed milestone" {
		t.Errorf("milestone title = %q, want %q", title, "Renamed milestone")
	}

	// Membership mismatch: the milestone belongs to goalID, not otherGoalID.
	reqMismatch := putJSON(t,
		"/api/admin/commitment/goals/"+otherGoalID.String()+"/milestones/"+mid.String(),
		map[string]any{"title": "Hijacked"})
	reqMismatch.SetPathValue("id", otherGoalID.String())
	reqMismatch.SetPathValue("mid", mid.String())
	recMismatch := serve(t, h.UpdateMilestone, reqMismatch)

	respMismatch := recMismatch.Result()
	defer respMismatch.Body.Close()
	bodyMismatch, _ := io.ReadAll(respMismatch.Body)

	if respMismatch.StatusCode != http.StatusNotFound {
		t.Fatalf("mismatch status = %d, want 404 (body=%s)", respMismatch.StatusCode, bodyMismatch)
	}
	if code := errCode(t, bodyMismatch); code != "NOT_FOUND" {
		t.Errorf("mismatch error.code = %q, want %q", code, "NOT_FOUND")
	}
	if err := testPool.QueryRow(t.Context(),
		`SELECT title FROM milestones WHERE id = $1`, mid,
	).Scan(&title); err != nil {
		t.Fatalf("reading milestone after rejected update: %v", err)
	}
	if title != "Renamed milestone" {
		t.Errorf("milestone title = %q after rejected cross-goal update, want %q", title, "Renamed milestone")
	}
}

// TestIntegration_Goal_DeleteMilestone drives DELETE /goals/{id}/milestones/{mid}:
// a completed milestone deletes with 204 (gaps left as-is), and a membership
// mismatch is a 404 that deletes nothing.
func TestIntegration_Goal_DeleteMilestone(t *testing.T) {
	truncate(t)
	h := newHandler()

	goalID := seedGoal(t, "Goal A")
	otherGoalID := seedGoal(t, "Goal B")
	mid := seedMilestone(t, goalID, "Done milestone", 0)
	keeper := seedMilestone(t, goalID, "Keeper milestone", 1)

	// Completed milestones are deletable — stamp completed_at first.
	if _, err := testPool.Exec(t.Context(),
		`UPDATE milestones SET completed_at = now() WHERE id = $1`, mid,
	); err != nil {
		t.Fatalf("completing milestone: %v", err)
	}

	// Membership mismatch first: nothing is deleted.
	reqMismatch := httptest.NewRequest(http.MethodDelete,
		"/api/admin/commitment/goals/"+otherGoalID.String()+"/milestones/"+mid.String(), nil)
	reqMismatch.SetPathValue("id", otherGoalID.String())
	reqMismatch.SetPathValue("mid", mid.String())
	recMismatch := serve(t, h.DeleteMilestone, reqMismatch)

	respMismatch := recMismatch.Result()
	defer respMismatch.Body.Close()
	bodyMismatch, _ := io.ReadAll(respMismatch.Body)

	if respMismatch.StatusCode != http.StatusNotFound {
		t.Fatalf("mismatch status = %d, want 404 (body=%s)", respMismatch.StatusCode, bodyMismatch)
	}
	if code := errCode(t, bodyMismatch); code != "NOT_FOUND" {
		t.Errorf("mismatch error.code = %q, want %q", code, "NOT_FOUND")
	}

	// Correct binding: 204 and the row is gone; the sibling keeps its
	// position (gaps left as-is).
	req := httptest.NewRequest(http.MethodDelete,
		"/api/admin/commitment/goals/"+goalID.String()+"/milestones/"+mid.String(), nil)
	req.SetPathValue("id", goalID.String())
	req.SetPathValue("mid", mid.String())
	rec := serve(t, h.DeleteMilestone, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body=%s)", rec.Code, rec.Body.String())
	}

	var count int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM milestones WHERE id = $1`, mid,
	).Scan(&count); err != nil {
		t.Fatalf("counting deleted milestone: %v", err)
	}
	if count != 0 {
		t.Errorf("milestone row count = %d after delete, want 0", count)
	}

	var keeperPos int32
	if err := testPool.QueryRow(t.Context(),
		`SELECT position FROM milestones WHERE id = $1`, keeper,
	).Scan(&keeperPos); err != nil {
		t.Fatalf("reading surviving milestone: %v", err)
	}
	if keeperPos != 1 {
		t.Errorf("surviving milestone position = %d, want 1 (gaps left as-is)", keeperPos)
	}
}

// TestIntegration_Goal_ListAreas asserts GET /areas returns the
// migration-seeded PARA rows with the {id, slug, name, sort_order} shape
// the goal-create selector consumes.
func TestIntegration_Goal_ListAreas(t *testing.T) {
	h := newHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/areas", nil)
	rec := httptest.NewRecorder()
	h.ListAreas(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	var env struct {
		Data []struct {
			ID        uuid.UUID `json:"id"`
			Slug      string    `json:"slug"`
			Name      string    `json:"name"`
			SortOrder int32     `json:"sort_order"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode areas response: %v (body=%s)", err, body)
	}
	if len(env.Data) == 0 {
		t.Fatalf("areas list is empty, want the migration-seeded PARA rows (body=%s)", body)
	}
	for i, a := range env.Data {
		if a.ID == uuid.Nil || a.Slug == "" || a.Name == "" {
			t.Errorf("areas[%d] = %+v, want non-zero id/slug/name", i, a)
		}
	}
	// Seeded rows are ordered by sort_order — verify monotonic non-decreasing.
	for i := 1; i < len(env.Data); i++ {
		if env.Data[i].SortOrder < env.Data[i-1].SortOrder {
			t.Errorf("areas not ordered by sort_order: [%d]=%d < [%d]=%d",
				i, env.Data[i].SortOrder, i-1, env.Data[i-1].SortOrder)
		}
	}
}

// TestIntegration_Goal_CreateArea drives POST /api/admin/commitment/areas
// through the admin middleware and asserts the owner direct-create invariants:
// the area persists status='active' / created_by=NULL (owner-made, no proposing
// agent), the slug is derived from the name, a blank name is a 400, and a
// duplicate slug is a 409. Created areas are cleaned up so the seeded PARA rows
// the ListAreas test relies on are not disturbed.
func TestIntegration_Goal_CreateArea(t *testing.T) {
	h := newHandler()

	const name = "Integration Create Area Probe"
	const wantSlug = "integration-create-area-probe"
	t.Cleanup(func() {
		// Direct-created areas are not in the truncate set (it skips areas to
		// preserve seeds). Remove this test's row by its derived slug.
		if _, err := testPool.Exec(context.Background(),
			`DELETE FROM areas WHERE slug = $1`, wantSlug,
		); err != nil {
			t.Errorf("cleanup area %q: %v", wantSlug, err)
		}
	})

	// Success: owner direct-create lands active, created_by NULL.
	req := postJSON(t, "/api/admin/commitment/areas", map[string]any{
		"name":        name,
		"description": "What this probe area covers.",
	})
	rec := serve(t, h.CreateArea, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", resp.StatusCode, body)
	}
	id := decodeID(t, body)

	var slug, status string
	var createdBy *string
	if err := testPool.QueryRow(t.Context(),
		`SELECT slug, status, created_by FROM areas WHERE id = $1`, id,
	).Scan(&slug, &status, &createdBy); err != nil {
		t.Fatalf("reading created area %s: %v", id, err)
	}
	if slug != wantSlug {
		t.Errorf("slug = %q, want %q (derived from name)", slug, wantSlug)
	}
	if status != "active" {
		t.Errorf("status = %q, want %q (owner direct-create is active)", status, "active")
	}
	if createdBy != nil {
		t.Errorf("created_by = %q, want NULL (owner-made, no proposing agent)", *createdBy)
	}

	// Blank name → 400. The handler rejects before the store.
	blankReq := postJSON(t, "/api/admin/commitment/areas", map[string]any{
		"name":        "",
		"description": "no name",
	})
	blankRec := serve(t, h.CreateArea, blankReq)
	if blankRec.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("blank-name status = %d, want 400", blankRec.Result().StatusCode)
	}

	// Duplicate slug → 409. A second create with a name deriving to the same
	// slug hits the unique(slug) constraint → ErrConflict → 409.
	dupReq := postJSON(t, "/api/admin/commitment/areas", map[string]any{
		"name":        "Integration Create Area PROBE",
		"description": "same derived slug",
	})
	dupRec := serve(t, h.CreateArea, dupReq)
	if dupRec.Result().StatusCode != http.StatusConflict {
		dupBody, _ := io.ReadAll(dupRec.Result().Body)
		t.Errorf("duplicate-slug status = %d, want 409 (body=%s)", dupRec.Result().StatusCode, dupBody)
	}
}

// TestIntegration_Goal_CreateArea_CJK pins that a pure Japanese/Chinese area
// name creates successfully — the slug keeps its CJK characters (Unicode-aware
// derivation) and the relaxed chk_area_slug_format accepts it against real
// PostgreSQL. Before the slug-restriction fix this returned 400 ("no slug-able
// characters") because the ascii-only deriver stripped every character.
func TestIntegration_Goal_CreateArea_CJK(t *testing.T) {
	h := newHandler()

	const name = "日本語学習"
	const wantSlug = "日本語学習"
	t.Cleanup(func() {
		if _, err := testPool.Exec(context.Background(),
			`DELETE FROM areas WHERE slug = $1`, wantSlug,
		); err != nil {
			t.Errorf("cleanup area %q: %v", wantSlug, err)
		}
	})

	req := postJSON(t, "/api/admin/commitment/areas", map[string]any{
		"name":        name,
		"description": "ヨルシカの歌詞を読む。",
	})
	rec := serve(t, h.CreateArea, req)
	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CJK area status = %d, want 201 (body=%s)", resp.StatusCode, body)
	}
	id := decodeID(t, body)

	var slug string
	if err := testPool.QueryRow(t.Context(),
		`SELECT slug FROM areas WHERE id = $1`, id,
	).Scan(&slug); err != nil {
		t.Fatalf("reading CJK area %s: %v", id, err)
	}
	if slug != wantSlug {
		t.Errorf("CJK slug = %q, want %q (Unicode-preserving derivation)", slug, wantSlug)
	}
}

// TestIntegration_Goal_ProposedExcludedFromList is the leak pin for proposed
// goals: a proposed goal is an inert draft that must NEVER appear in the
// normal goal list (GoalsByOptionalStatus with no status filter) nor in
// ActiveGoals, while a sibling not_started goal does appear in the list. It
// surfaces only when status='proposed' is asked for explicitly.
func TestIntegration_Goal_ProposedExcludedFromList(t *testing.T) {
	truncate(t)
	store := goal.NewStore(testPool)
	ctx := t.Context()

	var proposed, real uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO goals (title, status) VALUES ('Proposed Goal', 'proposed') RETURNING id`,
	).Scan(&proposed); err != nil {
		t.Fatalf("seeding proposed goal: %v", err)
	}
	if err := testPool.QueryRow(ctx,
		`INSERT INTO goals (title, status) VALUES ('Real Goal', 'not_started') RETURNING id`,
	).Scan(&real); err != nil {
		t.Fatalf("seeding not_started goal: %v", err)
	}

	// Default list (no status filter) must exclude the proposed goal.
	all, err := store.GoalsByOptionalStatus(ctx, nil)
	if err != nil {
		t.Fatalf("GoalsByOptionalStatus(nil): %v", err)
	}
	if containsGoal(all, proposed) {
		t.Error("proposed goal leaked into the default goal list (GoalsByOptionalStatus(nil))")
	}
	if !containsGoal(all, real) {
		t.Error("not_started goal missing from the default goal list")
	}

	// ActiveGoals only carries in_progress; a proposed goal must be absent.
	active, err := store.ActiveGoals(ctx)
	if err != nil {
		t.Fatalf("ActiveGoals: %v", err)
	}
	for i := range active {
		if active[i].ID == proposed {
			t.Error("proposed goal leaked into ActiveGoals")
		}
	}

	// Asking for proposed explicitly surfaces it — the triage path.
	proposedStatus := string(goal.StatusProposed)
	only, err := store.GoalsByOptionalStatus(ctx, &proposedStatus)
	if err != nil {
		t.Fatalf("GoalsByOptionalStatus(proposed): %v", err)
	}
	if !containsGoal(only, proposed) {
		t.Error("explicit status=proposed query did not return the proposed goal")
	}
	if containsGoal(only, real) {
		t.Error("explicit status=proposed query leaked the not_started goal")
	}
}

// TestIntegration_Goal_ProposedAreaExcludedFromSelector is the leak pin for
// proposed areas: a proposed area must NEVER appear in the Areas selector that
// backs the goal-create area picker, while a seeded active area does. The
// active-only resolver also refuses a proposed area, while the include-proposed
// resolver (used only by propose_goal) finds it.
func TestIntegration_Goal_ProposedAreaExcludedFromSelector(t *testing.T) {
	truncate(t)
	t.Cleanup(func() { deleteAreasBySlug(t, "proposed-theme") })
	store := goal.NewStore(testPool)
	ctx := t.Context()

	var proposedArea uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO areas (slug, name, status) VALUES ('proposed-theme', 'Proposed Theme', 'proposed') RETURNING id`,
	).Scan(&proposedArea); err != nil {
		t.Fatalf("seeding proposed area: %v", err)
	}

	areas, err := store.Areas(ctx)
	if err != nil {
		t.Fatalf("Areas: %v", err)
	}
	if len(areas) == 0 {
		t.Fatal("Areas returned no rows — expected the migration-seeded active areas")
	}
	for i := range areas {
		if areas[i].ID == proposedArea {
			t.Error("proposed area leaked into the Areas selector")
		}
	}

	// Active-only resolver refuses the proposed area.
	if _, err := store.AreaIDBySlugOrName(ctx, "proposed-theme"); !errors.Is(err, goal.ErrNotFound) {
		t.Errorf("AreaIDBySlugOrName(proposed) err = %v, want ErrNotFound", err)
	}
	// Include-proposed resolver (propose_goal's bundle case) finds it.
	got, err := store.AreaIDBySlugOrNameIncludingProposed(ctx, "proposed-theme")
	if err != nil {
		t.Fatalf("AreaIDBySlugOrNameIncludingProposed(proposed): %v", err)
	}
	if got != proposedArea {
		t.Errorf("AreaIDBySlugOrNameIncludingProposed = %s, want %s", got, proposedArea)
	}
}

// containsGoal reports whether any summary in the slice has the given id.
func containsGoal(summaries []goal.ActiveGoalSummary, id uuid.UUID) bool {
	for i := range summaries {
		if summaries[i].ID == id {
			return true
		}
	}
	return false
}

// seedProposedGoal inserts a proposed goal (optionally under an area) and
// returns its id.
func seedProposedGoal(t *testing.T, title string, areaID *uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title, status, area_id) VALUES ($1, 'proposed', $2) RETURNING id`,
		title, areaID,
	).Scan(&id); err != nil {
		t.Fatalf("seeding proposed goal %q: %v", title, err)
	}
	return id
}

// seedArea inserts an area in the given status and returns its id. Cleaned up
// by the caller — areas is not in truncate().
func seedArea(t *testing.T, slug, name, status string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO areas (slug, name, status) VALUES ($1, $2, $3) RETURNING id`,
		slug, name, status,
	).Scan(&id); err != nil {
		t.Fatalf("seeding %s area %q: %v", status, slug, err)
	}
	return id
}

// deleteAreasBySlug removes named areas in a fresh context (t.Cleanup runs
// after t.Context() is cancelled).
func deleteAreasBySlug(t *testing.T, slugs ...string) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(),
		`DELETE FROM areas WHERE slug = ANY($1)`, slugs,
	); err != nil {
		t.Fatalf("cleaning up seeded areas: %v", err)
	}
}

// TestIntegration_Goal_ActivateGoal drives POST /goals/{id}/activate: a
// proposed goal flips to not_started; a non-proposed goal is a 409 NOT_PROPOSED;
// a missing goal is a 404.
func TestIntegration_Goal_ActivateGoal(t *testing.T) {
	truncate(t)
	h := newHandler()

	proposed := seedProposedGoal(t, "Proposed goal", nil)
	real := seedGoal(t, "Real goal") // seedGoal inserts status=in_progress

	req := httptest.NewRequest(http.MethodPost, "/api/admin/commitment/goals/"+proposed.String()+"/activate", nil)
	req.SetPathValue("id", proposed.String())
	rec := serve(t, h.ActivateGoal, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("activate proposed goal status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var status string
	if err := testPool.QueryRow(t.Context(),
		`SELECT status FROM goals WHERE id = $1`, proposed,
	).Scan(&status); err != nil {
		t.Fatalf("reading activated goal: %v", err)
	}
	if status != string(goal.StatusNotStarted) {
		t.Errorf("activated goal status = %q, want %q", status, goal.StatusNotStarted)
	}

	// A non-proposed goal → 409 NOT_PROPOSED, untouched.
	reqReal := httptest.NewRequest(http.MethodPost, "/api/admin/commitment/goals/"+real.String()+"/activate", nil)
	reqReal.SetPathValue("id", real.String())
	recReal := serve(t, h.ActivateGoal, reqReal)
	if recReal.Code != http.StatusConflict {
		t.Fatalf("activate real goal status = %d, want 409 (body=%s)", recReal.Code, recReal.Body.String())
	}
	if code := errCode(t, recReal.Body.Bytes()); code != "NOT_PROPOSED" {
		t.Errorf("activate real goal error.code = %q, want NOT_PROPOSED", code)
	}

	// Missing goal → 404.
	missing := uuid.New()
	reqMiss := httptest.NewRequest(http.MethodPost, "/api/admin/commitment/goals/"+missing.String()+"/activate", nil)
	reqMiss.SetPathValue("id", missing.String())
	recMiss := serve(t, h.ActivateGoal, reqMiss)
	if recMiss.Code != http.StatusNotFound {
		t.Errorf("activate missing goal status = %d, want 404", recMiss.Code)
	}
}

// TestIntegration_Goal_ActivateArea drives POST /areas/{id}/activate: a
// proposed area flips to active.
func TestIntegration_Goal_ActivateArea(t *testing.T) {
	truncate(t)
	t.Cleanup(func() { deleteAreasBySlug(t, "to-activate") })
	h := newHandler()

	areaID := seedArea(t, "to-activate", "To Activate", "proposed")

	req := httptest.NewRequest(http.MethodPost, "/api/admin/commitment/areas/"+areaID.String()+"/activate", nil)
	req.SetPathValue("id", areaID.String())
	rec := serve(t, h.ActivateArea, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("activate area status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var status string
	if err := testPool.QueryRow(t.Context(),
		`SELECT status FROM areas WHERE id = $1`, areaID,
	).Scan(&status); err != nil {
		t.Fatalf("reading activated area: %v", err)
	}
	if status != "active" {
		t.Errorf("activated area status = %q, want active", status)
	}
}

// TestIntegration_Goal_RejectGoal drives DELETE /goals/{id}/proposed: a
// proposed goal (with milestones) is hard-deleted, milestones cascade; a real
// goal is a 409 NOT_PROPOSED left intact.
func TestIntegration_Goal_RejectGoal(t *testing.T) {
	truncate(t)
	h := newHandler()

	proposed := seedProposedGoal(t, "Proposed goal", nil)
	seedMilestone(t, proposed, "child milestone", 0)
	real := seedGoal(t, "Real goal")

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/commitment/goals/"+proposed.String()+"/proposed", nil)
	req.SetPathValue("id", proposed.String())
	rec := serve(t, h.RejectGoal, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("reject proposed goal status = %d, want 204 (body=%s)", rec.Code, rec.Body.String())
	}
	var goalCount, msCount int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM goals WHERE id = $1`, proposed,
	).Scan(&goalCount); err != nil {
		t.Fatalf("counting rejected goal: %v", err)
	}
	if goalCount != 0 {
		t.Errorf("rejected goal row count = %d, want 0", goalCount)
	}
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM milestones WHERE goal_id = $1`, proposed,
	).Scan(&msCount); err != nil {
		t.Fatalf("counting cascaded milestones: %v", err)
	}
	if msCount != 0 {
		t.Errorf("milestone count = %d after reject, want 0 (cascade)", msCount)
	}

	// A real goal → 409 NOT_PROPOSED, intact.
	reqReal := httptest.NewRequest(http.MethodDelete, "/api/admin/commitment/goals/"+real.String()+"/proposed", nil)
	reqReal.SetPathValue("id", real.String())
	recReal := serve(t, h.RejectGoal, reqReal)
	if recReal.Code != http.StatusConflict {
		t.Fatalf("reject real goal status = %d, want 409 (body=%s)", recReal.Code, recReal.Body.String())
	}
	var realCount int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM goals WHERE id = $1`, real,
	).Scan(&realCount); err != nil {
		t.Fatalf("counting real goal: %v", err)
	}
	if realCount != 1 {
		t.Errorf("real goal row count = %d after rejected delete, want 1 (untouched)", realCount)
	}
}

// TestIntegration_Goal_RejectAreaCascade drives DELETE /areas/{id}/proposed:
// rejecting a proposed area hard-deletes it AND its proposed child goals in one
// tx, while an ACTIVE child goal under the same area survives (area_id SET
// NULL). This is the bundle contract — the locked owner decision.
func TestIntegration_Goal_RejectAreaCascade(t *testing.T) {
	truncate(t)
	t.Cleanup(func() { deleteAreasBySlug(t, "bundle-area") })
	h := newHandler()

	areaID := seedArea(t, "bundle-area", "Bundle Area", "proposed")
	proposedChild := seedProposedGoal(t, "Proposed child goal", &areaID)

	// An active goal already filed under the area (e.g. a goal the owner
	// activated before deciding to reject the theme). It must survive.
	var activeChild uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title, status, area_id) VALUES ('Active child goal', 'in_progress', $1) RETURNING id`,
		areaID,
	).Scan(&activeChild); err != nil {
		t.Fatalf("seeding active child goal: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/commitment/areas/"+areaID.String()+"/proposed", nil)
	req.SetPathValue("id", areaID.String())
	rec := serve(t, h.RejectArea, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("reject area status = %d, want 204 (body=%s)", rec.Code, rec.Body.String())
	}

	// Area gone.
	var areaCount int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM areas WHERE id = $1`, areaID,
	).Scan(&areaCount); err != nil {
		t.Fatalf("counting rejected area: %v", err)
	}
	if areaCount != 0 {
		t.Errorf("rejected area row count = %d, want 0", areaCount)
	}

	// Proposed child goal gone (cascade).
	var proposedCount int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM goals WHERE id = $1`, proposedChild,
	).Scan(&proposedCount); err != nil {
		t.Fatalf("counting proposed child goal: %v", err)
	}
	if proposedCount != 0 {
		t.Errorf("proposed child goal count = %d after area reject, want 0 (bundle cascade)", proposedCount)
	}

	// Active child goal survives, unclassified (area_id SET NULL).
	var activeStatus string
	var activeArea *uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`SELECT status, area_id FROM goals WHERE id = $1`, activeChild,
	).Scan(&activeStatus, &activeArea); err != nil {
		t.Fatalf("reading active child goal: %v", err)
	}
	if activeStatus != "in_progress" {
		t.Errorf("active child status = %q after area reject, want in_progress (untouched)", activeStatus)
	}
	if activeArea != nil {
		t.Errorf("active child area_id = %v after area reject, want NULL (SET NULL)", activeArea)
	}
}

// TestIntegration_Goal_RejectArea_NotProposed drives DELETE /areas/{id}/proposed
// against an ACTIVE area: the handler returns 409 NOT_PROPOSED, and because
// RejectArea deletes proposed child goals BEFORE it guards the area's status,
// the whole request tx must roll back (ActorMiddleware commits only on 2xx/3xx)
// so neither the area nor a proposed child goal under it is deleted. This is the
// sibling of the RejectGoal not-proposed case for the area path.
func TestIntegration_Goal_RejectArea_NotProposed(t *testing.T) {
	truncate(t)
	t.Cleanup(func() { deleteAreasBySlug(t, "active-area") })
	h := newHandler()

	areaID := seedArea(t, "active-area", "Active Area", "active")
	proposedChild := seedProposedGoal(t, "Proposed child of active area", &areaID)

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/commitment/areas/"+areaID.String()+"/proposed", nil)
	req.SetPathValue("id", areaID.String())
	rec := serve(t, h.RejectArea, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("reject active area status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}

	// Area intact — a real (active) area is never deleted by the triage path.
	var areaCount int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM areas WHERE id = $1`, areaID,
	).Scan(&areaCount); err != nil {
		t.Fatalf("counting active area: %v", err)
	}
	if areaCount != 1 {
		t.Errorf("active area row count = %d after rejected delete, want 1 (untouched)", areaCount)
	}

	// Proposed child intact — the premature DeleteProposedGoalsByArea must have
	// rolled back with the 409 (no commit on a non-2xx response).
	var childCount int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM goals WHERE id = $1`, proposedChild,
	).Scan(&childCount); err != nil {
		t.Fatalf("counting proposed child goal: %v", err)
	}
	if childCount != 1 {
		t.Errorf("proposed child goal count = %d after rejected area delete, want 1 (tx rolled back)", childCount)
	}
}

// TestIntegration_Goal_ProposalsCount drives GET /proposals/count: it reports
// the number of proposed goals and proposed areas awaiting triage.
func TestIntegration_Goal_ProposalsCount(t *testing.T) {
	truncate(t)
	t.Cleanup(func() { deleteAreasBySlug(t, "count-area-1", "count-area-2") })
	h := newHandler()

	seedProposedGoal(t, "Proposed goal A", nil)
	seedProposedGoal(t, "Proposed goal B", nil)
	seedGoal(t, "Real goal") // not counted
	seedArea(t, "count-area-1", "Count Area 1", "proposed")
	seedArea(t, "count-area-2", "Count Area 2", "proposed")

	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/proposals/count", nil)
	rec := httptest.NewRecorder()
	h.ProposalsCount(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("proposals count status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var env struct {
		Data struct {
			Goals int64 `json:"proposed_goals"`
			Areas int64 `json:"proposed_areas"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode count response: %v (body=%s)", err, rec.Body.String())
	}
	if env.Data.Goals != 2 {
		t.Errorf("proposed_goals = %d, want 2", env.Data.Goals)
	}
	if env.Data.Areas != 2 {
		t.Errorf("proposed_areas = %d, want 2", env.Data.Areas)
	}
}

// TestIntegration_Goal_ProposalsIncludeProjects pins that the triage list and
// count surface proposed PROJECTS alongside proposed goals/areas — the project
// component the goal store cannot see is read through the project store the
// handler holds. A non-proposed project is excluded.
func TestIntegration_Goal_ProposalsIncludeProjects(t *testing.T) {
	truncate(t)
	t.Cleanup(func() {
		// goal's truncate does not touch projects; clean up the rows this test seeds.
		_, _ = testPool.Exec(context.Background(), `DELETE FROM projects`)
	})
	h := newHandlerWithProjects()

	var proposedID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO projects (slug, title, status, created_by)
		 VALUES ('triage-proj', 'Triage Proj', 'proposed', 'koopa0-dev') RETURNING id`,
	).Scan(&proposedID); err != nil {
		t.Fatalf("seeding proposed project: %v", err)
	}
	// A real project must NOT appear in the triage.
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO projects (slug, title, status) VALUES ('triage-real', 'Triage Real', 'in_progress')`,
	); err != nil {
		t.Fatalf("seeding real project: %v", err)
	}

	// Triage list includes the proposed project and excludes the real one.
	reqList := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/proposals", nil)
	recList := httptest.NewRecorder()
	h.Proposals(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Fatalf("proposals status = %d, want 200 (body=%s)", recList.Code, recList.Body.String())
	}
	var listEnv struct {
		Data struct {
			Projects []struct {
				ID uuid.UUID `json:"id"`
			} `json:"projects"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recList.Body.Bytes(), &listEnv); err != nil {
		t.Fatalf("decode proposals: %v (body=%s)", err, recList.Body.String())
	}
	if len(listEnv.Data.Projects) != 1 {
		t.Fatalf("triage projects len = %d, want 1 (real project excluded): %+v", len(listEnv.Data.Projects), listEnv.Data.Projects)
	}
	if listEnv.Data.Projects[0].ID != proposedID {
		t.Errorf("triage project = %s, want %s", listEnv.Data.Projects[0].ID, proposedID)
	}

	// Triage count reports the proposed project.
	reqCount := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/proposals/count", nil)
	recCount := httptest.NewRecorder()
	h.ProposalsCount(recCount, reqCount)
	if recCount.Code != http.StatusOK {
		t.Fatalf("proposals count status = %d, want 200", recCount.Code)
	}
	var countEnv struct {
		Data struct {
			Projects int64 `json:"proposed_projects"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recCount.Body.Bytes(), &countEnv); err != nil {
		t.Fatalf("decode count: %v (body=%s)", err, recCount.Body.String())
	}
	if countEnv.Data.Projects != 1 {
		t.Errorf("proposed_projects = %d, want 1", countEnv.Data.Projects)
	}
}

// TestIntegration_Goal_InvalidInput verifies that a foreign key pointing at a
// non-existent row (23503) surfaces as goal.ErrInvalidInput — which the handler
// maps to HTTP 400 — instead of a wrapped error rendered as an opaque 500. It
// covers a goal's area_id on both Create and Update, and a milestone's goal_id
// on CreateMilestone, since mapWriteError is shared across all three.
func TestIntegration_Goal_InvalidInput(t *testing.T) {
	truncate(t)
	store := goal.NewStore(testPool)
	ctx := t.Context()

	missing := uuid.New()

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create goal with non-existent area_id (foreign key 23503)",
			run: func() error {
				_, err := store.Create(ctx, &goal.CreateParams{
					Title:  "Orphan area goal",
					AreaID: &missing,
				})
				return err
			},
		},
		{
			name: "update goal with non-existent area_id (foreign key 23503)",
			run: func() error {
				id := seedGoal(t, "Area update target")
				_, err := store.Update(ctx, &goal.UpdateParams{
					ID:     id,
					AreaID: &missing,
				})
				return err
			},
		},
		{
			name: "create milestone under non-existent goal_id (foreign key 23503)",
			run: func() error {
				_, err := store.CreateMilestone(ctx, missing, "Orphan milestone", "", nil)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, goal.ErrInvalidInput) {
				t.Fatalf("err = %v, want goal.ErrInvalidInput", err)
			}
		})
	}
}
