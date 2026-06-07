// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles the testcontainers-backed admin handler tests
// for the learning plan package (W8 admin-surface coverage). Every mutation
// handler is driven through api.ActorMiddleware via httptest, never on a bare
// pool: plan handlers call h.mustAdminTx and 500 if the per-request tx is
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
