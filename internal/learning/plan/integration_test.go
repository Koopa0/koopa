// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles the testcontainers-backed admin handler tests
// for the learning plan package. Every mutation handler is driven through
// api.ActorMiddleware via httptest, never on a bare pool: plan handlers
// call h.mustAdminTx and 500 if the per-request tx is
// absent, and the audit triggers read koopa.actor from that tx. The production
// admin route (cmd/app/routes.go adminMid) always binds it.
//
// Coverage:
//   - Create — POST /api/admin/learning/plans → 201, plan persisted in
//     status=draft under the seeded leetcode domain.
//   - AddEntries — POST /plans/{id}/entries happy path (entries persisted) plus
//     the >maxEntriesPerRequest bounds rejection → 400. Guards #7.
//   - UpdateEntry — PUT /plans/{id}/entries/{entry_id}: the §13 completion
//     audit gate. status=completed REQUIRES completed_by_attempt_id AND a
//     non-blank reason; missing either → 400 AUDIT_REQUIRED. The happy path
//     (both present, on a real attempt-backed entry) → 200.
//   - UpdateStatus — PUT /plans/{id}/status: valid lifecycle transitions
//     persist and return the updated plan; unknown enum values → 400 at the
//     handler (never the DB CHECK); unknown plan id → 404.
//   - Reorder — PUT /plans/{id}/reorder: a full position swap persists
//     atomically despite UNIQUE (plan_id, position); duplicate positions,
//     duplicate entry ids, and foreign entries reject without writes.
//   - RemoveEntry — DELETE /plans/{id}/entries/{entry_id}: draft-only
//     removal → 204; active plans refuse with 409; unknown or foreign
//     entries → 404.
//
// Run with:
//
//	go test -tags=integration ./internal/learning/plan/...
package plan_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/learning/plan"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// learning_plans / learning_plan_entries audit triggers write
	// activity_events.actor (FK onto agents). Reconcile the builtin registry
	// once per suite, same as cmd/app/main.go at startup.
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

// truncate clears the plan tables (and their FK dependents) plus the learning
// targets/attempts the entry tests seed, so each case starts clean. The
// leetcode domain seeded by migration 002 is preserved.
func truncate(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(), `
		TRUNCATE
			learning_plan_entries,
			learning_plans,
			learning_attempt_observations,
			learning_attempts,
			learning_sessions,
			learning_targets,
			activity_events
		RESTART IDENTITY CASCADE`,
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// newHandler wires a plan.Handler against the shared test pool.
func newHandler() *plan.Handler {
	return plan.NewHandler(plan.NewStore(testPool), slog.Default())
}

// serve runs an admin request through ActorMiddleware (actor="human") into the
// handler, mirroring the production adminMid chain that binds the tx the plan
// handlers require.
func serve(t *testing.T, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	mid := api.ActorMiddleware(testPool, "human", slog.Default())
	wrapped := mid(h)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	return rec
}

// jsonReq builds a request with a JSON body and the admin content type.
func jsonReq(t *testing.T, method, target string, body any) *http.Request {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(buf))
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

// errorCode extracts error.code from an api.ErrorBody envelope.
func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode error envelope: %v (body=%s)", err, body)
	}
	return env.Error.Code
}

// seedTarget inserts a leetcode learning_target and returns its id. external_id
// is derived from the test name so repeated calls in the shared container do not
// collide on the (domain, external_id) partial unique index.
func seedTarget(t *testing.T, title string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_targets (domain, title, external_id, created_by)
		 VALUES ('leetcode', $1, $2, 'human') RETURNING id`,
		title, t.Name()+"::"+title,
	).Scan(&id); err != nil {
		t.Fatalf("seeding learning_target %q: %v", title, err)
	}
	return id
}

// seedDraftPlan creates a draft leetcode plan via the Create handler and returns
// its id. Used by the entry tests, which need a parent plan to attach to.
func seedDraftPlan(t *testing.T, h *plan.Handler, title string) uuid.UUID {
	t.Helper()
	req := jsonReq(t, http.MethodPost, "/api/admin/learning/plans", map[string]any{
		"title":  title,
		"domain": "leetcode",
	})
	rec := serve(t, h.Create, req)
	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("seedDraftPlan: status = %d, want 201 (body=%s)", resp.StatusCode, body)
	}
	return decodeID(t, body)
}

// TestIntegration_Plan_Create drives POST /api/admin/learning/plans and asserts
// the plan persists in status=draft under the leetcode domain.
func TestIntegration_Plan_Create(t *testing.T) {
	truncate(t)
	h := newHandler()

	req := jsonReq(t, http.MethodPost, "/api/admin/learning/plans", map[string]any{
		"title":       "Two Pointers Drill",
		"description": "Two-week two-pointer focus.",
		"domain":      "leetcode",
	})
	rec := serve(t, h.Create, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", resp.StatusCode, body)
	}
	id := decodeID(t, body)

	var title, domain, status string
	if err := testPool.QueryRow(t.Context(),
		`SELECT title, domain, status FROM learning_plans WHERE id = $1`, id,
	).Scan(&title, &domain, &status); err != nil {
		t.Fatalf("reading created plan %s: %v", id, err)
	}
	if title != "Two Pointers Drill" {
		t.Errorf("title = %q, want %q", title, "Two Pointers Drill")
	}
	if domain != "leetcode" {
		t.Errorf("domain = %q, want %q", domain, "leetcode")
	}
	if status != string(plan.StatusDraft) {
		t.Errorf("status = %q, want %q (create always lands draft)", status, plan.StatusDraft)
	}
}

// TestIntegration_Plan_AddEntries_HappyPath seeds two targets, adds both as
// entries, and asserts they persist with ascending positions.
func TestIntegration_Plan_AddEntries_HappyPath(t *testing.T) {
	truncate(t)
	h := newHandler()

	planID := seedDraftPlan(t, h, "Add Entries Plan")
	t1 := seedTarget(t, "Two Sum")
	t2 := seedTarget(t, "Valid Anagram")

	req := jsonReq(t, http.MethodPost, "/api/admin/learning/plans/"+planID.String()+"/entries", map[string]any{
		"entries": []map[string]any{
			{"learning_target_id": t1.String()},
			{"learning_target_id": t2.String()},
		},
	})
	req.SetPathValue("id", planID.String())
	rec := serve(t, h.AddEntries, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", resp.StatusCode, body)
	}

	// Both targets must be attached as entries under this plan.
	var count int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM learning_plan_entries WHERE plan_id = $1`, planID,
	).Scan(&count); err != nil {
		t.Fatalf("counting entries: %v", err)
	}
	if count != 2 {
		t.Errorf("entry count = %d, want 2", count)
	}
}

// TestIntegration_Plan_AddEntries_BoundsRejected guards #7: a single
// AddEntries call carrying more than maxEntriesPerRequest (100) entries must be
// rejected with 400 before any row lands, so a runaway client cannot blow up
// the plan in one round trip.
func TestIntegration_Plan_AddEntries_BoundsRejected(t *testing.T) {
	truncate(t)
	h := newHandler()

	planID := seedDraftPlan(t, h, "Bounds Plan")

	// 101 entries — one over the ceiling. The IDs need not reference real
	// targets: the handler rejects on length before touching the store.
	entries := make([]map[string]any, 101)
	for i := range entries {
		entries[i] = map[string]any{"learning_target_id": uuid.New().String()}
	}

	req := jsonReq(t, http.MethodPost, "/api/admin/learning/plans/"+planID.String()+"/entries", map[string]any{
		"entries": entries,
	})
	req.SetPathValue("id", planID.String())
	rec := serve(t, h.AddEntries, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for >100 entries (body=%s)", resp.StatusCode, body)
	}

	// Nothing must have been written for this plan.
	var count int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM learning_plan_entries WHERE plan_id = $1`, planID,
	).Scan(&count); err != nil {
		t.Fatalf("counting entries: %v", err)
	}
	if count != 0 {
		t.Errorf("entry count = %d, want 0 (bounds rejection must precede any write)", count)
	}
}

// TestIntegration_Plan_UpdateEntry_CompletionAuditGate exercises the §13
// completion audit gate end-to-end through the handler. Marking an entry
// completed REQUIRES completed_by_attempt_id AND a non-blank reason; the
// handler rejects either omission with 400 AUDIT_REQUIRED before any write. The
// happy path supplies both (with a real attempt on the entry's target) and
// reaches 200, persisting the audit fields.
func TestIntegration_Plan_UpdateEntry_CompletionAuditGate(t *testing.T) {
	truncate(t)
	h := newHandler()

	planID := seedDraftPlan(t, h, "Completion Gate Plan")
	target := seedTarget(t, "House Robber")

	// Add one entry on the target.
	addReq := jsonReq(t, http.MethodPost, "/api/admin/learning/plans/"+planID.String()+"/entries", map[string]any{
		"entries": []map[string]any{{"learning_target_id": target.String()}},
	})
	addReq.SetPathValue("id", planID.String())
	if rec := serve(t, h.AddEntries, addReq); rec.Code != http.StatusCreated {
		t.Fatalf("add_entries setup: status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}

	var entryID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`SELECT id FROM learning_plan_entries WHERE plan_id = $1`, planID,
	).Scan(&entryID); err != nil {
		t.Fatalf("locating entry: %v", err)
	}

	// Seed a session + a real attempt on the SAME target so the happy-path
	// completion has an aligned completed_by_attempt_id (the store aligns the
	// attempt's learning_target_id to the entry's).
	var sessionID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_sessions (domain, session_mode)
		 VALUES ('leetcode', 'practice') RETURNING id`,
	).Scan(&sessionID); err != nil {
		t.Fatalf("seeding session: %v", err)
	}
	var attemptID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_attempts (session_id, learning_target_id, paradigm, outcome)
		 VALUES ($1, $2, 'problem_solving', 'solved_independent') RETURNING id`,
		sessionID, target,
	).Scan(&attemptID); err != nil {
		t.Fatalf("seeding attempt: %v", err)
	}

	updatePath := "/api/admin/learning/plans/" + planID.String() + "/entries/" + entryID.String()

	// Negative cases: the handler gate must reject completion missing the
	// audit fields with 400 AUDIT_REQUIRED, before any DB transition.
	rejectTests := []struct {
		name string
		body map[string]any
	}{
		{
			name: "missing both attempt id and reason",
			body: map[string]any{"status": "completed"},
		},
		{
			name: "missing completed_by_attempt_id",
			body: map[string]any{"status": "completed", "reason": "solved on attempt #2"},
		},
		{
			name: "blank reason",
			body: map[string]any{
				"status":                  "completed",
				"completed_by_attempt_id": attemptID.String(),
				"reason":                  "",
			},
		},
	}
	for _, tc := range rejectTests {
		t.Run(tc.name, func(t *testing.T) {
			req := jsonReq(t, http.MethodPut, updatePath, tc.body)
			req.SetPathValue("id", planID.String())
			req.SetPathValue("entry_id", entryID.String())
			rec := serve(t, h.UpdateEntry, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
			if code := errorCode(t, rec.Body.Bytes()); code != "AUDIT_REQUIRED" {
				t.Errorf("error.code = %q, want %q", code, "AUDIT_REQUIRED")
			}
			// The entry must still be uncompleted after a rejected call.
			var status string
			if err := testPool.QueryRow(t.Context(),
				`SELECT status FROM learning_plan_entries WHERE id = $1`, entryID,
			).Scan(&status); err != nil {
				t.Fatalf("reading entry status: %v", err)
			}
			if status == string(plan.EntryCompleted) {
				t.Errorf("entry status = %q, want it NOT completed after a rejected gate", status)
			}
		})
	}

	// Happy path: both audit fields present, aligned attempt → 200 completed,
	// audit fields persisted.
	t.Run("completion with attempt id and reason succeeds", func(t *testing.T) {
		req := jsonReq(t, http.MethodPut, updatePath, map[string]any{
			"status":                  "completed",
			"completed_by_attempt_id": attemptID.String(),
			"reason":                  "solved_independent on attempt #1, clean implementation",
		})
		req.SetPathValue("id", planID.String())
		req.SetPathValue("entry_id", entryID.String())
		rec := serve(t, h.UpdateEntry, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}

		var status string
		var completedBy *uuid.UUID
		var reason *string
		if err := testPool.QueryRow(t.Context(),
			`SELECT status, completed_by_attempt_id, reason
			 FROM learning_plan_entries WHERE id = $1`, entryID,
		).Scan(&status, &completedBy, &reason); err != nil {
			t.Fatalf("reading completed entry: %v", err)
		}
		if status != string(plan.EntryCompleted) {
			t.Errorf("status = %q, want %q", status, plan.EntryCompleted)
		}
		if completedBy == nil || *completedBy != attemptID {
			t.Errorf("completed_by_attempt_id = %v, want %s", completedBy, attemptID)
		}
		if reason == nil || !strings.Contains(*reason, "solved_independent") {
			t.Errorf("reason = %v, want the audit reason persisted", reason)
		}
	})
}

// seedEntries adds one fresh target per title to the plan through the
// AddEntries handler and returns the created entry IDs ordered by position
// (positions 1..n, assigned by the handler).
func seedEntries(t *testing.T, h *plan.Handler, planID uuid.UUID, titles ...string) []uuid.UUID {
	t.Helper()
	entries := make([]map[string]any, len(titles))
	for i, title := range titles {
		entries[i] = map[string]any{"learning_target_id": seedTarget(t, title).String()}
	}
	req := jsonReq(t, http.MethodPost, "/api/admin/learning/plans/"+planID.String()+"/entries", map[string]any{
		"entries": entries,
	})
	req.SetPathValue("id", planID.String())
	if rec := serve(t, h.AddEntries, req); rec.Code != http.StatusCreated {
		t.Fatalf("seedEntries: status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}

	rows, err := testPool.Query(t.Context(),
		`SELECT id FROM learning_plan_entries WHERE plan_id = $1 ORDER BY position`, planID)
	if err != nil {
		t.Fatalf("seedEntries: reading entry ids: %v", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("seedEntries: scanning entry id: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("seedEntries: iterating entry ids: %v", err)
	}
	if len(ids) != len(titles) {
		t.Fatalf("seedEntries: got %d entries, want %d", len(ids), len(titles))
	}
	return ids
}

// entryPositions reads the plan's current id → position map for persistence
// assertions.
func entryPositions(t *testing.T, planID uuid.UUID) map[uuid.UUID]int32 {
	t.Helper()
	rows, err := testPool.Query(t.Context(),
		`SELECT id, position FROM learning_plan_entries WHERE plan_id = $1`, planID)
	if err != nil {
		t.Fatalf("reading entry positions: %v", err)
	}
	defer rows.Close()
	got := make(map[uuid.UUID]int32)
	for rows.Next() {
		var id uuid.UUID
		var pos int32
		if err := rows.Scan(&id, &pos); err != nil {
			t.Fatalf("scanning entry position: %v", err)
		}
		got[id] = pos
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating entry positions: %v", err)
	}
	return got
}

// TestIntegration_Plan_List_EntryCounts drives GET /api/admin/learning/plans
// (management view) and the ?domain= filtered path, asserting each list row
// carries entry_total / entry_done for the admin Entries/Progress columns.
func TestIntegration_Plan_List_EntryCounts(t *testing.T) {
	truncate(t)
	h := newHandler()

	withEntries := seedDraftPlan(t, h, "Counts Plan A")
	entryIDs := seedEntries(t, h, withEntries, "Counts T1", "Counts T2", "Counts T3")
	// Complete one entry directly — the §13 handler gate is exercised by the
	// CompletionAuditGate test; the list counts only read persisted status.
	if _, err := testPool.Exec(t.Context(),
		`UPDATE learning_plan_entries SET status = 'completed', completed_at = now() WHERE id = $1`,
		entryIDs[0],
	); err != nil {
		t.Fatalf("completing entry: %v", err)
	}
	withoutEntries := seedDraftPlan(t, h, "Counts Plan B")

	type listRow struct {
		ID         uuid.UUID `json:"id"`
		EntryTotal int64     `json:"entry_total"`
		EntryDone  int64     `json:"entry_done"`
	}
	fetch := func(t *testing.T, target string) map[uuid.UUID]listRow {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, target, http.NoBody)
		rec := serve(t, h.List, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("list status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		var env struct {
			Data []listRow `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode list: %v (body=%s)", err, rec.Body.String())
		}
		rows := make(map[uuid.UUID]listRow, len(env.Data))
		for _, r := range env.Data {
			rows[r.ID] = r
		}
		return rows
	}

	listTests := []struct {
		name   string
		target string
	}{
		{name: "management list", target: "/api/admin/learning/plans"},
		{name: "domain filtered list", target: "/api/admin/learning/plans?domain=leetcode"},
	}
	for _, tt := range listTests {
		t.Run(tt.name, func(t *testing.T) {
			want := map[uuid.UUID]listRow{
				withEntries:    {ID: withEntries, EntryTotal: 3, EntryDone: 1},
				withoutEntries: {ID: withoutEntries, EntryTotal: 0, EntryDone: 0},
			}
			if diff := cmp.Diff(want, fetch(t, tt.target)); diff != "" {
				t.Errorf("plan list counts mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestIntegration_Plan_Detail_GoalName asserts the detail envelope carries
// the linked goal's title (goal_name) so the meta strip shows the title
// instead of a UUID, and an empty string for goal-less plans.
func TestIntegration_Plan_Detail_GoalName(t *testing.T) {
	truncate(t)
	h := newHandler()

	// truncate() leaves goals alone (other suites own that table) — seed a
	// uniquely-titled goal and clean it up explicitly. The goals audit
	// trigger defaults the actor to 'system' outside ActorMiddleware.
	var goalID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title) VALUES ('Plan Detail Goal Name Goal') RETURNING id`,
	).Scan(&goalID); err != nil {
		t.Fatalf("seeding goal: %v", err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(context.Background(),
			`DELETE FROM goals WHERE id = $1`, goalID); err != nil {
			t.Logf("cleanup goal: %v", err)
		}
	})

	// Plan bound to the goal — created through the handler so goal_id takes
	// the same path production uses.
	req := jsonReq(t, http.MethodPost, "/api/admin/learning/plans", map[string]any{
		"title":   "Goal Name Plan",
		"domain":  "leetcode",
		"goal_id": goalID.String(),
	})
	rec := serve(t, h.Create, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create plan with goal: status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	planWithGoal := decodeID(t, rec.Body.Bytes())

	planWithout := seedDraftPlan(t, h, "Goalless Plan")

	detailGoalName := func(t *testing.T, id uuid.UUID) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet,
			"/api/admin/learning/plans/"+id.String(), http.NoBody)
		req.SetPathValue("id", id.String())
		rec := serve(t, h.Detail, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("detail status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				GoalName *string `json:"goal_name"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode detail: %v (body=%s)", err, rec.Body.String())
		}
		if env.Data.GoalName == nil {
			t.Fatalf("goal_name missing from detail envelope (body=%s)", rec.Body.String())
		}
		return *env.Data.GoalName
	}

	if got := detailGoalName(t, planWithGoal); got != "Plan Detail Goal Name Goal" {
		t.Errorf("goal_name = %q, want %q", got, "Plan Detail Goal Name Goal")
	}
	if got := detailGoalName(t, planWithout); got != "" {
		t.Errorf("goal_name = %q, want empty string for a goal-less plan", got)
	}
}

// TestIntegration_Plan_UpdateStatus drives PUT /plans/{id}/status through the
// lifecycle enum gate: valid transitions persist and return the updated plan,
// an unknown enum value rejects with 400 at the handler before the DB CHECK
// can turn it into a 500, and an unknown plan id maps to 404. Cases run in
// order — each builds on the status the previous one left behind.
func TestIntegration_Plan_UpdateStatus(t *testing.T) {
	truncate(t)
	h := newHandler()
	planID := seedDraftPlan(t, h, "Status Lifecycle Plan")

	tests := []struct {
		name       string
		id         string
		body       map[string]any
		wantCode   int
		wantStatus string // status expected in the DB after the call
	}{
		{name: "draft to active", id: planID.String(), body: map[string]any{"status": "active"}, wantCode: http.StatusOK, wantStatus: "active"},
		{name: "active to paused", id: planID.String(), body: map[string]any{"status": "paused"}, wantCode: http.StatusOK, wantStatus: "paused"},
		{name: "invalid enum rejected", id: planID.String(), body: map[string]any{"status": "archived"}, wantCode: http.StatusBadRequest, wantStatus: "paused"},
		{name: "missing status rejected", id: planID.String(), body: map[string]any{}, wantCode: http.StatusBadRequest, wantStatus: "paused"},
		{name: "unknown plan returns 404", id: uuid.New().String(), body: map[string]any{"status": "active"}, wantCode: http.StatusNotFound, wantStatus: "paused"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := jsonReq(t, http.MethodPut, "/api/admin/learning/plans/"+tt.id+"/status", tt.body)
			req.SetPathValue("id", tt.id)
			rec := serve(t, h.UpdateStatus, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.wantCode == http.StatusOK {
				var env struct {
					Data plan.Plan `json:"data"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
					t.Fatalf("decoding updated plan: %v (body=%s)", err, rec.Body.String())
				}
				if string(env.Data.Status) != tt.wantStatus {
					t.Errorf("response status = %q, want %q", env.Data.Status, tt.wantStatus)
				}
			}
			var dbStatus string
			if err := testPool.QueryRow(t.Context(),
				`SELECT status FROM learning_plans WHERE id = $1`, planID,
			).Scan(&dbStatus); err != nil {
				t.Fatalf("reading plan status: %v", err)
			}
			if dbStatus != tt.wantStatus {
				t.Errorf("DB status = %q, want %q", dbStatus, tt.wantStatus)
			}
		})
	}
}

// TestIntegration_Plan_Reorder_SwapPersists reorders a three-entry plan into
// reverse order — a full swap that would violate UNIQUE (plan_id, position)
// without the two-phase update — and asserts the new positions persist and
// the response envelope carries the entries in the new order.
func TestIntegration_Plan_Reorder_SwapPersists(t *testing.T) {
	truncate(t)
	h := newHandler()
	planID := seedDraftPlan(t, h, "Reorder Plan")
	ids := seedEntries(t, h, planID, "Reorder A", "Reorder B", "Reorder C") // positions 1,2,3

	req := jsonReq(t, http.MethodPut, "/api/admin/learning/plans/"+planID.String()+"/reorder", map[string]any{
		"entries": []map[string]any{
			{"plan_entry_id": ids[0].String(), "position": 3},
			{"plan_entry_id": ids[1].String(), "position": 2},
			{"plan_entry_id": ids[2].String(), "position": 1},
		},
	})
	req.SetPathValue("id", planID.String())
	rec := serve(t, h.Reorder, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	want := map[uuid.UUID]int32{ids[0]: 3, ids[1]: 2, ids[2]: 1}
	if diff := cmp.Diff(want, entryPositions(t, planID)); diff != "" {
		t.Errorf("persisted positions mismatch (-want +got):\n%s", diff)
	}

	// The response is the detail envelope ordered by the NEW positions.
	var env struct {
		Data struct {
			Entries []struct {
				PlanEntryID uuid.UUID `json:"plan_entry_id"`
				Position    int32     `json:"position"`
			} `json:"entries"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decoding detail envelope: %v (body=%s)", err, rec.Body.String())
	}
	if len(env.Data.Entries) != 3 {
		t.Fatalf("envelope entries = %d, want 3 (body=%s)", len(env.Data.Entries), rec.Body.String())
	}
	wantOrder := []uuid.UUID{ids[2], ids[1], ids[0]}
	for i, e := range env.Data.Entries {
		if e.PlanEntryID != wantOrder[i] {
			t.Errorf("envelope entries[%d] = %s, want %s", i, e.PlanEntryID, wantOrder[i])
		}
	}
}

// TestIntegration_Plan_Reorder_Rejections drives the reorder request gates
// end-to-end: duplicate positions, duplicate entry ids, entries of another
// plan, unknown plans, and collisions with entries left out of the request
// all reject — and no positions change.
func TestIntegration_Plan_Reorder_Rejections(t *testing.T) {
	truncate(t)
	h := newHandler()
	planID := seedDraftPlan(t, h, "Reorder Reject Plan")
	ids := seedEntries(t, h, planID, "Reject A", "Reject B", "Reject C") // positions 1,2,3
	otherPlan := seedDraftPlan(t, h, "Reorder Other Plan")
	otherIDs := seedEntries(t, h, otherPlan, "Reject Other A")

	before := entryPositions(t, planID)

	tests := []struct {
		name     string
		planID   string
		entries  []map[string]any
		wantCode int
	}{
		{
			name:   "duplicate position",
			planID: planID.String(),
			entries: []map[string]any{
				{"plan_entry_id": ids[0].String(), "position": 5},
				{"plan_entry_id": ids[1].String(), "position": 5},
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name:   "duplicate entry id",
			planID: planID.String(),
			entries: []map[string]any{
				{"plan_entry_id": ids[0].String(), "position": 4},
				{"plan_entry_id": ids[0].String(), "position": 5},
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "entry of another plan",
			planID:   planID.String(),
			entries:  []map[string]any{{"plan_entry_id": otherIDs[0].String(), "position": 1}},
			wantCode: http.StatusNotFound,
		},
		{
			name:     "unknown plan",
			planID:   uuid.New().String(),
			entries:  []map[string]any{{"plan_entry_id": ids[0].String(), "position": 1}},
			wantCode: http.StatusNotFound,
		},
		{
			// ids[1] holds position 2 and is not part of the request, so
			// moving ids[0] onto 2 must refuse instead of tripping the
			// unique constraint.
			name:     "collision with untouched entry",
			planID:   planID.String(),
			entries:  []map[string]any{{"plan_entry_id": ids[0].String(), "position": 2}},
			wantCode: http.StatusConflict,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := jsonReq(t, http.MethodPut, "/api/admin/learning/plans/"+tt.planID+"/reorder", map[string]any{
				"entries": tt.entries,
			})
			req.SetPathValue("id", tt.planID)
			rec := serve(t, h.Reorder, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tt.wantCode, rec.Body.String())
			}
			if diff := cmp.Diff(before, entryPositions(t, planID)); diff != "" {
				t.Errorf("positions changed after rejected reorder (-want +got):\n%s", diff)
			}
		})
	}
}

// TestIntegration_Plan_RemoveEntry covers the draft-only removal invariant:
// deleting an entry from a draft plan returns 204 and removes exactly that
// row; the same delete against an active plan refuses with 409 and the row
// survives; unknown entries and entries of a different plan map to 404.
// Subtests run in order — activation happens between the draft and active
// cases.
func TestIntegration_Plan_RemoveEntry(t *testing.T) {
	truncate(t)
	h := newHandler()
	planID := seedDraftPlan(t, h, "Remove Plan")
	ids := seedEntries(t, h, planID, "Remove A", "Remove B")
	otherPlan := seedDraftPlan(t, h, "Remove Other Plan")
	otherIDs := seedEntries(t, h, otherPlan, "Remove Other A")

	remove := func(t *testing.T, planID, entryID string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodDelete,
			"/api/admin/learning/plans/"+planID+"/entries/"+entryID, http.NoBody)
		req.SetPathValue("id", planID)
		req.SetPathValue("entry_id", entryID)
		return serve(t, h.RemoveEntry, req)
	}
	count := func(t *testing.T, planID uuid.UUID) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM learning_plan_entries WHERE plan_id = $1`, planID,
		).Scan(&n); err != nil {
			t.Fatalf("counting entries: %v", err)
		}
		return n
	}

	t.Run("unknown entry returns 404", func(t *testing.T) {
		if rec := remove(t, planID.String(), uuid.New().String()); rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("entry of another plan returns 404", func(t *testing.T) {
		rec := remove(t, planID.String(), otherIDs[0].String())
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
		}
		if got := count(t, otherPlan); got != 1 {
			t.Errorf("other plan entry count = %d, want 1 (cross-plan delete must not land)", got)
		}
	})

	t.Run("draft removal succeeds with 204", func(t *testing.T) {
		rec := remove(t, planID.String(), ids[0].String())
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 (body=%s)", rec.Code, rec.Body.String())
		}
		if got := count(t, planID); got != 1 {
			t.Errorf("entry count = %d, want 1", got)
		}
		var remaining uuid.UUID
		if err := testPool.QueryRow(t.Context(),
			`SELECT id FROM learning_plan_entries WHERE plan_id = $1`, planID,
		).Scan(&remaining); err != nil {
			t.Fatalf("reading remaining entry: %v", err)
		}
		if remaining != ids[1] {
			t.Errorf("remaining entry = %s, want %s", remaining, ids[1])
		}
	})

	t.Run("active plan refuses removal with 409", func(t *testing.T) {
		if _, err := testPool.Exec(t.Context(),
			`UPDATE learning_plans SET status = 'active' WHERE id = $1`, planID,
		); err != nil {
			t.Fatalf("activating plan: %v", err)
		}
		rec := remove(t, planID.String(), ids[1].String())
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
		}
		if code := errorCode(t, rec.Body.Bytes()); code != "CONFLICT" {
			t.Errorf("error.code = %q, want %q", code, "CONFLICT")
		}
		if got := count(t, planID); got != 1 {
			t.Errorf("entry count = %d, want 1 (refused delete must not land)", got)
		}
	})
}
