// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles the testcontainers-backed admin handler tests
// for the todo package. Read-only handlers (authMid in production) run
// directly against the shared pool-bound store; mutation handlers run
// through api.ActorMiddleware exactly like the production adminMid chain,
// because the todos audit trigger reads koopa.actor from the per-request
// transaction.
//
// Coverage:
//   - Recurring — seed weekday- and interval-mode recurring todos; assert the
//     compute-on-read due_today bucket matches the recurrence rule + last
//     completion (weekday bit, completed-today exclusion, interval never-done).
//   - History — seed a completed todo; assert it appears in the default
//     completed-since view.
//   - List — state filter (single value, comma-separated list, invalid
//     element → 400), the created_by projection, and the description
//     projection the inbox triage surfaces render.
//   - Advance(activate) — someday → todo happy path + wrong-state 400.
//
// Run with:
//
//	go test -tags=integration ./internal/todo/...
package todo_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/testdb"
	"github.com/Koopa0/koopa/internal/todo"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.NewPool()
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
	return todo.NewHandler(todo.NewStore(testPool), time.UTC, slog.Default())
}

// serveRead runs a read request directly into the handler (no middleware —
// these are authMid read handlers that need no tx).
func serveRead(t *testing.T, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// serve runs an admin mutation request through ActorMiddleware
// (actor="human", the admin-write convention) into the given handler,
// mirroring the production adminMid chain.
func serve(t *testing.T, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	mid := api.ActorMiddleware(testPool, "human", slog.Default())
	wrapped := mid(h)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	return rec
}

// seedTodo inserts a todo row in the given state and returns its id.
// done rows get completed_at stamped — chk_todo_completed_at_consistency
// requires it.
func seedTodo(t *testing.T, title, state, createdBy string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state, created_by, completed_at)
		 VALUES ($1, $2::todo_state, $3, CASE WHEN $2::todo_state = 'done' THEN now() END)
		 RETURNING id`,
		title, state, createdBy,
	).Scan(&id); err != nil {
		t.Fatalf("seeding todo %q (state=%s): %v", title, state, err)
	}
	return id
}

// advanceReq builds the POST {id}/advance request for the given action.
func advanceReq(t *testing.T, id uuid.UUID, action string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/api/admin/commitment/todos/"+id.String()+"/advance",
		strings.NewReader(`{"action":"`+action+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", id.String())
	return req
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

	// today's ISODOW bit (Mon=bit0 .. Sun=bit6), computed independently of the
	// SQL query so a Go/SQL bitmask disagreement surfaces as a failure.
	isodow := int(time.Now().UTC().Weekday()) // Go: Sun=0 .. Sat=6
	if isodow == 0 {
		isodow = 7 // ISODOW: Sunday = 7
	}
	todayBit := 1 << (isodow - 1)
	const allWeekdays = 127
	today := time.Now().UTC().Format(time.DateOnly)

	seed := func(title string, weekdays, interval *int, unit, lastCompleted *string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := testPool.QueryRow(t.Context(),
			`INSERT INTO todos (title, state, recur_weekdays, recur_interval, recur_unit, last_completed_on, created_by)
			 VALUES ($1, 'todo', $2::smallint, $3::int, $4, $5::date, 'human') RETURNING id`,
			title, weekdays, interval, unit, lastCompleted,
		).Scan(&id); err != nil {
			t.Fatalf("seeding %q: %v", title, err)
		}
		return id
	}
	iptr := func(i int) *int { return &i }
	sptr := func(s string) *string { return &s }

	dueWeekday := seed("Daily Japanese", iptr(allWeekdays), nil, nil, nil)
	dueTodayOnly := seed("Today only", iptr(todayBit), nil, nil, nil)
	notTodayWeekday := seed("Other days only", iptr(allWeekdays^todayBit), nil, nil, nil)
	doneTodayWeekday := seed("Already done today", iptr(allWeekdays), nil, nil, sptr(today))
	dueInterval := seed("Every 3 days, never done", nil, iptr(3), sptr("days"), nil)

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
			All []struct {
				ID uuid.UUID `json:"id"`
			} `json:"all"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode recurring response: %v (body=%s)", err, body)
	}
	due := make(map[uuid.UUID]struct{}, len(env.Data.DueToday))
	for _, d := range env.Data.DueToday {
		due[d.ID] = struct{}{}
	}

	wantDue := map[string]uuid.UUID{
		"all-weekday todo":     dueWeekday,
		"today-only weekday":   dueTodayOnly,
		"interval, never done": dueInterval,
	}
	for name, id := range wantDue {
		if _, ok := due[id]; !ok {
			t.Errorf("%s (%s) missing from due_today (body=%s)", name, id, body)
		}
	}
	wantNotDue := map[string]uuid.UUID{
		"weekday excluding today": notTodayWeekday,
		"already completed today": doneTodayWeekday,
	}
	for name, id := range wantNotDue {
		if _, ok := due[id]; ok {
			t.Errorf("%s (%s) must NOT be in due_today (body=%s)", name, id, body)
		}
	}

	// The `all` bucket (routines overview) carries every active recurring
	// schedule, including the off-day and already-done-today ones that the
	// due_today bucket excludes — that is the whole point of the manage-all view.
	all := make(map[uuid.UUID]struct{}, len(env.Data.All))
	for _, a := range env.Data.All {
		all[a.ID] = struct{}{}
	}
	for name, id := range map[string]uuid.UUID{
		"all-weekday todo":        dueWeekday,
		"today-only weekday":      dueTodayOnly,
		"interval, never done":    dueInterval,
		"weekday excluding today": notTodayWeekday,
		"already completed today": doneTodayWeekday,
	} {
		if _, ok := all[id]; !ok {
			t.Errorf("%s (%s) missing from all (body=%s)", name, id, body)
		}
	}
}

// TestIntegration_Todo_Recurring_Interval exercises the interval-mode
// recurrence arithmetic in RecurringTodoItemsDueToday:
//
//	@today >= last_completed_on + (recur_interval || ' ' || recur_unit)::interval
//
// The weekday-mode test only covers last_completed_on=NULL for interval rows;
// this test drives the actual date arithmetic with hand-computed
// last_completed_on values relative to today, so a wrong interval addition
// (e.g. off-by-one, or wrong unit) surfaces as an inclusion/exclusion failure.
func TestIntegration_Todo_Recurring_Interval(t *testing.T) {
	truncate(t)
	store := todo.NewStore(testPool)
	ctx := t.Context()

	// today is the date the query is evaluated against (date-only, UTC).
	today := time.Now().UTC().Truncate(24 * time.Hour)
	daysAgo := func(n int) *string {
		s := today.AddDate(0, 0, -n).Format(time.DateOnly)
		return &s
	}

	// seedInterval inserts an active interval-mode recurring todo with the given
	// last_completed_on and returns its id.
	seedInterval := func(title string, interval int, unit string, lastCompleted *string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := testPool.QueryRow(ctx,
			`INSERT INTO todos (title, state, recur_interval, recur_unit, last_completed_on, created_by)
			 VALUES ($1, 'todo', $2::int, $3, $4::date, 'human') RETURNING id`,
			title, interval, unit, lastCompleted,
		).Scan(&id); err != nil {
			t.Fatalf("seeding %q: %v", title, err)
		}
		return id
	}

	// every 3 days, completed exactly 3 days ago → today == lastCompleted + 3d → due.
	dueExact := seedInterval("3d, completed exactly 3 days ago", 3, "days", daysAgo(3))
	// every 3 days, completed 2 days ago (interval-1) → today < lastCompleted + 3d → NOT due.
	notDueYet := seedInterval("3d, completed 2 days ago", 3, "days", daysAgo(2))
	// every 3 days, completed 5 days ago (well past) → due.
	dueOverdue := seedInterval("3d, completed 5 days ago", 3, "days", daysAgo(5))
	// every 2 weeks, completed exactly 14 days ago → today == lastCompleted + 14d → due.
	dueWeeks := seedInterval("2w, completed exactly 14 days ago", 2, "weeks", daysAgo(14))
	// every 2 weeks, completed 13 days ago → NOT due yet.
	notDueWeeks := seedInterval("2w, completed 13 days ago", 2, "weeks", daysAgo(13))
	// every 1 month, completed 20 days ago → NOT due (a month is >= 28 days).
	notDueMonth := seedInterval("1mo, completed 20 days ago", 1, "months", daysAgo(20))

	items, err := store.RecurringItemsDueToday(ctx, today)
	if err != nil {
		t.Fatalf("RecurringItemsDueToday: %v", err)
	}
	due := make(map[uuid.UUID]struct{}, len(items))
	for i := range items {
		due[items[i].ID] = struct{}{}
	}

	wantDue := map[string]uuid.UUID{
		"3d completed exactly 3 days ago":  dueExact,
		"3d completed 5 days ago":          dueOverdue,
		"2w completed exactly 14 days ago": dueWeeks,
	}
	for name, id := range wantDue {
		if _, ok := due[id]; !ok {
			t.Errorf("%s (%s) missing from due_today", name, id)
		}
	}
	wantNotDue := map[string]uuid.UUID{
		"3d completed 2 days ago (interval-1)": notDueYet,
		"2w completed 13 days ago":             notDueWeeks,
		"1mo completed 20 days ago":            notDueMonth,
	}
	for name, id := range wantNotDue {
		if _, ok := due[id]; ok {
			t.Errorf("%s (%s) must NOT be in due_today", name, id)
		}
	}
}

// TestIntegration_Todo_History seeds the three resolution kinds the Complete
// ("已了結") view collects — a one-time done todo, a dropped (dismissed) todo,
// and a still-active recurring routine with a recent occurrence — and asserts
// all three appear, while an untouched pending todo does not.
func TestIntegration_Todo_History(t *testing.T) {
	truncate(t)
	h := newHandler()

	var done, dropped, recurring uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state, completed_at, created_by)
		 VALUES ('Shipped the feature', 'done', now(), 'human') RETURNING id`,
	).Scan(&done); err != nil {
		t.Fatalf("seeding completed todo: %v", err)
	}
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state, created_by)
		 VALUES ('Won''t do this', 'dismissed', 'human') RETURNING id`,
	).Scan(&dropped); err != nil {
		t.Fatalf("seeding dismissed todo: %v", err)
	}
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state, recur_weekdays, last_completed_on, created_by)
		 VALUES ('Morning Japanese', 'todo', 127, current_date, 'human') RETURNING id`,
	).Scan(&recurring); err != nil {
		t.Fatalf("seeding recurring todo: %v", err)
	}
	// A pending todo with no resolution must NOT surface in the Complete view.
	pending := seedTodo(t, "Still to do", "todo", "human")

	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/todos/history", nil)
	rec := serveRead(t, h.History, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	ids := dataIDs(t, body)
	for name, id := range map[string]uuid.UUID{"done": done, "dropped": dropped, "recurring": recurring} {
		if _, ok := ids[id]; !ok {
			t.Errorf("%s todo %s missing from Complete view (body=%s)", name, id, body)
		}
	}
	if _, ok := ids[pending]; ok {
		t.Errorf("pending todo %s must NOT appear in Complete view (body=%s)", pending, body)
	}
}

// TestIntegration_Todo_List_SingleStateFilter pins the backward-compatible
// single-value state filter and the created_by projection: a list row must
// carry the creator identity, not serialize "".
func TestIntegration_Todo_List_SingleStateFilter(t *testing.T) {
	truncate(t)
	h := newHandler()

	someday := seedTodo(t, "Someday item", "someday", "claude")
	seedTodo(t, "Inbox item", "inbox", "human")

	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/todos?state=someday", nil)
	rec := serveRead(t, h.List, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	var env struct {
		Data []struct {
			ID        uuid.UUID `json:"id"`
			State     string    `json:"state"`
			CreatedBy string    `json:"created_by"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode list response: %v (body=%s)", err, body)
	}
	if len(env.Data) != 1 {
		t.Fatalf("state=someday returned %d rows, want 1 (body=%s)", len(env.Data), body)
	}
	if env.Data[0].ID != someday {
		t.Errorf("filtered row id = %s, want %s", env.Data[0].ID, someday)
	}
	if env.Data[0].State != "someday" {
		t.Errorf("filtered row state = %q, want %q", env.Data[0].State, "someday")
	}
	if env.Data[0].CreatedBy != "claude" {
		t.Errorf("created_by = %q, want %q (list projection must carry the creator)", env.Data[0].CreatedBy, "claude")
	}
}

// TestIntegration_Todo_List_DescriptionProjection pins the wire shape the
// inbox triage surfaces depend on: the admin list projection carries the
// capture's free-text description (e.g. hermes context) and leaves it empty
// when the capture has none. Regression guard — before the description was
// added to BacklogTodoItems, this field was silently dropped.
func TestIntegration_Todo_List_DescriptionProjection(t *testing.T) {
	truncate(t)
	h := newHandler()

	const detail = "check HNSW vs IVFFlat tradeoffs"
	var withDesc uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state, created_by, description)
		 VALUES ($1, 'inbox'::todo_state, 'hermes', $2)
		 RETURNING id`,
		"Hermes capture", detail,
	).Scan(&withDesc); err != nil {
		t.Fatalf("seeding inbox todo with description: %v", err)
	}
	bare := seedTodo(t, "Bare capture", "inbox", "human")

	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/todos?state=inbox", nil)
	rec := serveRead(t, h.List, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	var env struct {
		Data []struct {
			ID          uuid.UUID `json:"id"`
			Description string    `json:"description"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode list response: %v (body=%s)", err, body)
	}

	got := make(map[uuid.UUID]string, len(env.Data))
	for _, d := range env.Data {
		got[d.ID] = d.Description
	}
	if got[withDesc] != detail {
		t.Errorf("description for hermes capture = %q, want %q (list projection must carry the capture detail)", got[withDesc], detail)
	}
	if got[bare] != "" {
		t.Errorf("description for bare capture = %q, want empty", got[bare])
	}
}

// TestIntegration_Todo_List_MultiStateFilter pins the comma-separated state
// filter: state=inbox,todo returns rows from both states and excludes done —
// the server-side exclusion the GTD backlog view relies on.
func TestIntegration_Todo_List_MultiStateFilter(t *testing.T) {
	truncate(t)
	h := newHandler()

	inbox := seedTodo(t, "Inbox item", "inbox", "human")
	open := seedTodo(t, "Open item", "todo", "human")
	seedTodo(t, "Done item", "done", "human")

	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/todos?state=inbox,todo", nil)
	rec := serveRead(t, h.List, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	ids := dataIDs(t, body)
	if len(ids) != 2 {
		t.Fatalf("state=inbox,todo returned %d rows, want 2 (body=%s)", len(ids), body)
	}
	if _, ok := ids[inbox]; !ok {
		t.Errorf("inbox todo %s missing from multi-state list (body=%s)", inbox, body)
	}
	if _, ok := ids[open]; !ok {
		t.Errorf("todo-state todo %s missing from multi-state list (body=%s)", open, body)
	}
}

// TestIntegration_Todo_List_InvalidStateElement pins enum validation at the
// handler boundary: any invalid element in the comma list is a 400, never a
// PostgreSQL cast error surfacing as 500.
func TestIntegration_Todo_List_InvalidStateElement(t *testing.T) {
	truncate(t)
	h := newHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/todos?state=todo,bogus", nil)
	rec := serveRead(t, h.List, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid state element (body=%s)", resp.StatusCode, body)
	}

	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode error envelope: %v (body=%s)", err, body)
	}
	if env.Error.Code != "BAD_REQUEST" {
		t.Errorf("error.code = %q, want %q", env.Error.Code, "BAD_REQUEST")
	}
}

// TestIntegration_Todo_Advance_Activate drives the activate verb through the
// middleware: a someday row transitions to todo, in the response and in the
// database.
func TestIntegration_Todo_Advance_Activate(t *testing.T) {
	truncate(t)
	h := newHandler()

	id := seedTodo(t, "Revive me", "someday", "human")

	rec := serve(t, h.Advance, advanceReq(t, id, "activate"))

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	var env struct {
		Data struct {
			ID    uuid.UUID `json:"id"`
			State string    `json:"state"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode activate response: %v (body=%s)", err, body)
	}
	if env.Data.ID != id {
		t.Errorf("response id = %s, want %s", env.Data.ID, id)
	}
	if env.Data.State != "todo" {
		t.Errorf("response state = %q, want %q", env.Data.State, "todo")
	}

	var state string
	if err := testPool.QueryRow(t.Context(),
		`SELECT state FROM todos WHERE id = $1`, id,
	).Scan(&state); err != nil {
		t.Fatalf("reading activated todo: %v", err)
	}
	if state != "todo" {
		t.Errorf("db state = %q after activate, want %q", state, "todo")
	}
}

// TestIntegration_Todo_Advance_Activate_WrongState pins the SQL state guard:
// activate on a non-someday row is a 400 INVALID_TRANSITION (mirroring the
// drop guard), and the row keeps its state.
func TestIntegration_Todo_Advance_Activate_WrongState(t *testing.T) {
	truncate(t)
	h := newHandler()

	id := seedTodo(t, "Still raw", "inbox", "human")

	rec := serve(t, h.Advance, advanceReq(t, id, "activate"))

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for activate on inbox row (body=%s)", resp.StatusCode, body)
	}

	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode error envelope: %v (body=%s)", err, body)
	}
	if env.Error.Code != "INVALID_TRANSITION" {
		t.Errorf("error.code = %q, want %q", env.Error.Code, "INVALID_TRANSITION")
	}

	var state string
	if err := testPool.QueryRow(t.Context(),
		`SELECT state FROM todos WHERE id = $1`, id,
	).Scan(&state); err != nil {
		t.Fatalf("reading todo after rejected activate: %v", err)
	}
	if state != "inbox" {
		t.Errorf("db state = %q after rejected activate, want %q (unchanged)", state, "inbox")
	}
}

// TestIntegration_Todo_InvalidInput verifies that a client-supplied project_id
// pointing at a non-existent project (foreign key 23503) surfaces as
// todo.ErrInvalidInput — which the handler maps to HTTP 400 — instead of a
// wrapped error that api.HandleError would render as an opaque 500. The store's
// mapWriteError is shared by Create and Update, so the table drives both paths.
func TestIntegration_Todo_InvalidInput(t *testing.T) {
	truncate(t)
	store := todo.NewStore(testPool)
	ctx := t.Context()

	missing := uuid.New()

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create with non-existent project_id (foreign key 23503)",
			run: func() error {
				_, err := store.Create(ctx, &todo.CreateParams{
					Title:     "Orphan todo",
					ProjectID: &missing,
					CreatedBy: "human",
				})
				return err
			},
		},
		{
			name: "update with non-existent project_id (foreign key 23503)",
			run: func() error {
				existing := seedTodo(t, "Update target", "todo", "human")
				_, err := store.Update(ctx, &todo.UpdateParams{
					ID:        existing,
					ProjectID: &missing,
				})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, todo.ErrInvalidInput) {
				t.Fatalf("err = %v, want todo.ErrInvalidInput", err)
			}
		})
	}
}

// seedDueTodo inserts a todo in the given state with the given due date and
// returns its id. archived/dismissed/someday/inbox keep completed_at NULL
// (chk_todo_completed_at_consistency), so a due-dated terminal todo is a valid
// row — the exact shape that must NOT appear in the active date-relative reads.
func seedDueTodo(t *testing.T, title, state string, due time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state, due, created_by)
		 VALUES ($1, $2::todo_state, $3, 'human') RETURNING id`,
		title, state, due,
	).Scan(&id); err != nil {
		t.Fatalf("seeding due todo %q (state=%s): %v", title, state, err)
	}
	return id
}

// idSet collects the ids from a PendingDetail slice for membership assertions.
func idSet(items []todo.PendingDetail) map[uuid.UUID]struct{} {
	out := make(map[uuid.UUID]struct{}, len(items))
	for i := range items {
		out[items[i].ID] = struct{}{}
	}
	return out
}

// TestIntegration_Todo_DateReads_ExcludeTerminal pins the regression fix:
// resolve_todo added the terminal states archived/dismissed, but the morning
// brief overdue/today reads (and the Today page) only excluded done/someday/
// inbox, so a self-closed todo leaked back as active. After the fix, an archived
// or dismissed todo — even one carrying an overdue due date — must NOT appear in
// OverdueItems or ItemsDueOn, while an active overdue todo still does.
func TestIntegration_Todo_DateReads_ExcludeTerminal(t *testing.T) {
	truncate(t)
	store := todo.NewStore(testPool)
	ctx := t.Context()

	// One due date in the past so every row is "overdue" relative to today.
	due := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	today := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	active := seedDueTodo(t, "Active overdue", "todo", due)
	archived := seedDueTodo(t, "Archived overdue", "archived", due)
	dismissed := seedDueTodo(t, "Dismissed overdue", "dismissed", due)

	// Overdue: the active row only; terminal rows must be excluded.
	overdue, err := store.OverdueItems(ctx, today)
	if err != nil {
		t.Fatalf("OverdueItems: %v", err)
	}
	got := idSet(overdue)
	if _, ok := got[active]; !ok {
		t.Errorf("OverdueItems missing active overdue todo %s", active)
	}
	if _, ok := got[archived]; ok {
		t.Errorf("OverdueItems includes archived todo %s, want excluded", archived)
	}
	if _, ok := got[dismissed]; ok {
		t.Errorf("OverdueItems includes dismissed todo %s, want excluded", dismissed)
	}

	// Due-on (the Today section / Today page): same exclusion on the due date.
	dueOn, err := store.ItemsDueOn(ctx, due)
	if err != nil {
		t.Fatalf("ItemsDueOn: %v", err)
	}
	got = idSet(dueOn)
	if _, ok := got[active]; !ok {
		t.Errorf("ItemsDueOn missing active todo %s", active)
	}
	if _, ok := got[archived]; ok {
		t.Errorf("ItemsDueOn includes archived todo %s, want excluded", archived)
	}
	if _, ok := got[dismissed]; ok {
		t.Errorf("ItemsDueOn includes dismissed todo %s, want excluded", dismissed)
	}
}

// TestIntegration_Todo_InProgressItems_ExcludesRecurring pins that the Today
// "Active" query returns only NON-recurring in_progress work. A recurring todo
// left in_progress must never appear in Active — otherwise, once its occurrence
// is completed (and it drops out of recurring-due-today), it would resurface in
// Active the same day instead of waiting for its next due day.
func TestIntegration_Todo_InProgressItems_ExcludesRecurring(t *testing.T) {
	truncate(t)
	store := todo.NewStore(testPool)
	ctx := t.Context()

	// A plain in_progress one-off — must appear in Active.
	oneOff := seedTodo(t, "Review 2 Go lessons", "in_progress", "human")
	// A recurring (daily) in_progress todo — must NOT appear in Active.
	var recurring uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO todos (title, state, recur_weekdays, created_by)
		 VALUES ('Daily Japanese vocab', 'in_progress', 127::smallint, 'human') RETURNING id`,
	).Scan(&recurring); err != nil {
		t.Fatalf("seeding recurring in_progress todo: %v", err)
	}

	items, err := store.InProgressItems(ctx)
	if err != nil {
		t.Fatalf("InProgressItems: %v", err)
	}
	got := make(map[uuid.UUID]struct{}, len(items))
	for i := range items {
		got[items[i].ID] = struct{}{}
	}
	if _, ok := got[oneOff]; !ok {
		t.Errorf("InProgressItems missing the one-off in_progress todo %s", oneOff)
	}
	if _, ok := got[recurring]; ok {
		t.Errorf("InProgressItems includes recurring todo %s; recurring work belongs to the Recurring section, not Active", recurring)
	}
}

// TestIntegration_Recurring_TimezoneDateRoundTrips proves the day boundary is
// the owner's civil date, not UTC. The handler computes "today" as midnight in
// Asia/Taipei (e.g. 2026-06-30 00:00+08 == 2026-06-29 16:00 UTC). This test
// passes that exact value through the recurrence read + occurrence stamp and
// asserts the ::date casts resolve to the TAIPEI date (06-30), not the UTC date
// (06-29) of the same instant — the off-by-one trap a naive timezone change hits.
func TestIntegration_Recurring_TimezoneDateRoundTrips(t *testing.T) {
	truncate(t)
	store := todo.NewStore(testPool)
	ctx := t.Context()

	taipei, err := time.LoadLocation("Asia/Taipei")
	if err != nil {
		t.Fatalf("loading Asia/Taipei: %v", err)
	}
	// Taipei civil date 2026-06-30, the instant straddling the UTC boundary.
	today := time.Date(2026, 6, 30, 0, 0, 0, 0, taipei)

	// Daily (all-weekday) recurring todo, last completed the Taipei day before.
	var id uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO todos (title, state, recur_weekdays, last_completed_on, created_by)
		 VALUES ('Daily vocab', 'todo', 127::smallint, '2026-06-29'::date, 'human') RETURNING id`,
	).Scan(&id); err != nil {
		t.Fatalf("seeding recurring todo: %v", err)
	}

	// Due today: last completion (06-29) is before the Taipei today (06-30).
	due, err := store.RecurringItemsDueToday(ctx, today)
	if err != nil {
		t.Fatalf("RecurringItemsDueToday: %v", err)
	}
	if !containsID(due, id) {
		t.Fatalf("todo last-completed 06-29 must be due on Taipei 06-30 (got %d due)", len(due))
	}

	// Complete today's occurrence using the same Taipei-midnight value.
	if err := store.CompleteOccurrenceByID(ctx, id, today); err != nil {
		t.Fatalf("CompleteOccurrenceByID: %v", err)
	}

	// The stamp must be the Taipei civil date (06-30), NOT the UTC date (06-29)
	// of that instant — this is the assertion that catches the timezone trap.
	var stamped time.Time
	if err := testPool.QueryRow(ctx,
		`SELECT last_completed_on FROM todos WHERE id = $1`, id,
	).Scan(&stamped); err != nil {
		t.Fatalf("reading last_completed_on: %v", err)
	}
	if got := stamped.Format(time.DateOnly); got != "2026-06-30" {
		t.Errorf("last_completed_on = %q, want 2026-06-30 (Taipei civil date, not the UTC 06-29)", got)
	}

	// And it must now drop out of due-today (completed for the Taipei day).
	due2, err := store.RecurringItemsDueToday(ctx, today)
	if err != nil {
		t.Fatalf("RecurringItemsDueToday after complete: %v", err)
	}
	if containsID(due2, id) {
		t.Error("recurring todo completed for Taipei today must not still be due today")
	}
}

// containsID reports whether items holds a todo with the given id.
func containsID(items []todo.Item, id uuid.UUID) bool {
	for i := range items {
		if items[i].ID == id {
			return true
		}
	}
	return false
}

// TestIntegration_Todo_RecurringExcludedFromDueSections pins D3/K1: a recurring
// todo that ALSO has a due date must NOT double-list — it belongs to the
// Recurring section only, never the due-based overdue/due-today/upcoming
// sections. A non-recurring todo with the same due date still appears there.
func TestIntegration_Todo_RecurringExcludedFromDueSections(t *testing.T) {
	truncate(t)
	store := todo.NewStore(testPool)
	ctx := t.Context()
	today := time.Now().UTC()

	seedDue := func(title, state string, due string, weekdays *int) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := testPool.QueryRow(ctx,
			`INSERT INTO todos (title, state, due, recur_weekdays, created_by)
			 VALUES ($1, $2::todo_state, $3::date, $4::smallint, 'human') RETURNING id`,
			title, state, due, weekdays,
		).Scan(&id); err != nil {
			t.Fatalf("seeding %q: %v", title, err)
		}
		return id
	}
	all := 127
	yesterday := today.AddDate(0, 0, -1).Format(time.DateOnly)
	todayStr := today.Format(time.DateOnly)

	// Non-recurring overdue + due-today: must appear in the due sections.
	plainOverdue := seedDue("plain overdue", "todo", yesterday, nil)
	plainToday := seedDue("plain due today", "todo", todayStr, nil)
	// Recurring with a past/today due: must be EXCLUDED from the due sections.
	recurOverdue := seedDue("recurring + overdue due", "todo", yesterday, &all)
	recurToday := seedDue("recurring + today due", "todo", todayStr, &all)

	overdue, err := store.OverdueItems(ctx, today)
	if err != nil {
		t.Fatalf("OverdueItems: %v", err)
	}
	od := idSet(overdue)
	if _, ok := od[plainOverdue]; !ok {
		t.Errorf("OverdueItems missing the plain overdue todo %s", plainOverdue)
	}
	if _, ok := od[recurOverdue]; ok {
		t.Errorf("OverdueItems includes recurring todo %s — recurring must not double-list in the overdue section", recurOverdue)
	}

	dueOn, err := store.ItemsDueOn(ctx, today)
	if err != nil {
		t.Fatalf("ItemsDueOn: %v", err)
	}
	don := idSet(dueOn)
	if _, ok := don[plainToday]; !ok {
		t.Errorf("ItemsDueOn missing the plain due-today todo %s", plainToday)
	}
	if _, ok := don[recurToday]; ok {
		t.Errorf("ItemsDueOn includes recurring todo %s — recurring must not double-list in the due-today section", recurToday)
	}

	// Upcoming (due-in-range): a plain future todo appears; a recurring one with
	// a future due does not (the third due-based query carries the same guard).
	tomorrow := today.AddDate(0, 0, 1).Format(time.DateOnly)
	plainUpcoming := seedDue("plain upcoming", "todo", tomorrow, nil)
	recurUpcoming := seedDue("recurring + upcoming due", "todo", tomorrow, &all)
	upcoming, err := store.ItemsDueInRange(ctx, today, today.AddDate(0, 0, 7))
	if err != nil {
		t.Fatalf("ItemsDueInRange: %v", err)
	}
	up := idSet(upcoming)
	if _, ok := up[plainUpcoming]; !ok {
		t.Errorf("ItemsDueInRange missing the plain upcoming todo %s", plainUpcoming)
	}
	if _, ok := up[recurUpcoming]; ok {
		t.Errorf("ItemsDueInRange includes recurring todo %s — recurring must not double-list in the upcoming section", recurUpcoming)
	}

	// Both recurring todos still surface in the Recurring section (daily mask).
	due, err := store.RecurringItemsDueToday(ctx, today)
	if err != nil {
		t.Fatalf("RecurringItemsDueToday: %v", err)
	}
	if !containsID(due, recurOverdue) || !containsID(due, recurToday) {
		t.Errorf("recurring todos must still appear in RecurringItemsDueToday (got %d)", len(due))
	}
}

// TestIntegration_Todo_CompleteOccurrence_StateGuard pins D5: completing a
// recurring occurrence only applies to an ACTIVE (todo/in_progress) todo. A
// recurring todo still in inbox (e.g. captured-but-unclarified) must not be
// stampable — the guard returns ErrNotFound and leaves last_completed_on NULL,
// preventing the contradictory "completed today but never clarified" state.
func TestIntegration_Todo_CompleteOccurrence_StateGuard(t *testing.T) {
	truncate(t)
	store := todo.NewStore(testPool)
	ctx := t.Context()

	var inboxRecurring uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO todos (title, state, recur_weekdays, created_by)
		 VALUES ('captured daily routine', 'inbox', 127::smallint, 'human') RETURNING id`,
	).Scan(&inboxRecurring); err != nil {
		t.Fatalf("seeding recurring inbox todo: %v", err)
	}

	// Admin (by-id) path: must be rejected as not-found by the state guard.
	if err := store.CompleteOccurrenceByID(ctx, inboxRecurring, time.Now().UTC()); !errors.Is(err, todo.ErrNotFound) {
		t.Errorf("CompleteOccurrenceByID on an inbox recurring todo = %v, want ErrNotFound (state guard)", err)
	}
	// Caller-scoped path: same guard.
	if err := store.CompleteOccurrence(ctx, inboxRecurring, "human", time.Now().UTC()); !errors.Is(err, todo.ErrNotFound) {
		t.Errorf("CompleteOccurrence on an inbox recurring todo = %v, want ErrNotFound (state guard)", err)
	}

	var stamped *time.Time
	if err := testPool.QueryRow(ctx,
		`SELECT last_completed_on FROM todos WHERE id = $1`, inboxRecurring,
	).Scan(&stamped); err != nil {
		t.Fatalf("reading last_completed_on: %v", err)
	}
	if stamped != nil {
		t.Errorf("last_completed_on = %v, want NULL — the guard must not stamp a non-active recurring todo", stamped)
	}
}

// recurrenceReq builds the PUT {id}/recurrence request with the given JSON body.
func recurrenceReq(t *testing.T, id uuid.UUID, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut,
		"/api/admin/commitment/todos/"+id.String()+"/recurrence",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", id.String())
	return req
}

// TestIntegration_Todo_Advance_Complete_Recurring pins the recurring-aware
// admin complete: completing a recurring todo stamps last_completed_on for
// today's occurrence but keeps it recurring (state unchanged, completed_at
// NULL) — it must NOT move to done, which would kill the recurrence
// (RecurringItemsDueToday excludes done). This is the bug where the admin
// complete button diverged from MCP resolve_todo's occurrence semantics.
func TestIntegration_Todo_Advance_Complete_Recurring(t *testing.T) {
	truncate(t)
	h := newHandler()

	// Seed a daily (all-weekday) recurring todo in 'todo' state.
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state, recur_weekdays, created_by)
		 VALUES ('Daily Japanese vocab', 'todo', 127::smallint, 'human') RETURNING id`,
	).Scan(&id); err != nil {
		t.Fatalf("seeding recurring todo: %v", err)
	}

	rec := serve(t, h.Advance, advanceReq(t, id, "complete"))
	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}

	var (
		state         string
		completedAt   *time.Time
		lastCompleted *time.Time
	)
	if err := testPool.QueryRow(t.Context(),
		`SELECT state, completed_at, last_completed_on FROM todos WHERE id = $1`, id,
	).Scan(&state, &completedAt, &lastCompleted); err != nil {
		t.Fatalf("reading completed recurring todo: %v", err)
	}
	if state == "done" {
		t.Errorf("state = %q after completing a recurring todo, want it kept recurring (not done)", state)
	}
	if completedAt != nil {
		t.Errorf("completed_at = %v, want NULL for a recurring occurrence", completedAt)
	}
	if lastCompleted == nil {
		t.Fatal("last_completed_on is NULL, want today's date stamped")
	}
	wantDay := time.Now().UTC().Format(time.DateOnly)
	if gotDay := lastCompleted.Format(time.DateOnly); gotDay != wantDay {
		t.Errorf("last_completed_on = %q, want %q (today)", gotDay, wantDay)
	}
}

// TestIntegration_Todo_Recurrence_SetThenClear pins the admin recurrence route:
// setting weekday-mode writes the mask, and clearing recurrence also resets
// last_completed_on so chk_todo_last_completed_requires_recurrence holds (a
// one-shot carries no occurrence stamp). Without the reset, clearing a
// previously-completed recurring todo would violate the CHECK and surface 500.
func TestIntegration_Todo_Recurrence_SetThenClear(t *testing.T) {
	truncate(t)
	h := newHandler()

	id := seedTodo(t, "Maybe-routine", "todo", "human")

	// Set weekday recurrence (Mon-Sun = daily).
	rec := serve(t, h.Recurrence, recurrenceReq(t, id,
		`{"weekdays":["mon","tue","wed","thu","fri","sat","sun"]}`))
	if rec.Result().StatusCode != http.StatusOK {
		body, _ := io.ReadAll(rec.Result().Body)
		t.Fatalf("set recurrence status = %d, want 200 (body=%s)", rec.Result().StatusCode, body)
	}
	var weekdays *int16
	if err := testPool.QueryRow(t.Context(),
		`SELECT recur_weekdays FROM todos WHERE id = $1`, id,
	).Scan(&weekdays); err != nil {
		t.Fatalf("reading recurrence: %v", err)
	}
	if weekdays == nil || *weekdays != 127 {
		t.Fatalf("recur_weekdays = %v, want 127", weekdays)
	}

	// Complete today's occurrence so last_completed_on is set.
	if rec := serve(t, h.Advance, advanceReq(t, id, "complete")); rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("complete occurrence status = %d, want 200", rec.Result().StatusCode)
	}

	// Clear recurrence — must also clear last_completed_on (the invariant).
	rec = serve(t, h.Recurrence, recurrenceReq(t, id, `{"clear":true}`))
	if rec.Result().StatusCode != http.StatusOK {
		body, _ := io.ReadAll(rec.Result().Body)
		t.Fatalf("clear recurrence status = %d, want 200 (body=%s)", rec.Result().StatusCode, body)
	}
	var (
		clearedWeekdays *int16
		clearedInterval *int32
		lastCompleted   *time.Time
	)
	if err := testPool.QueryRow(t.Context(),
		`SELECT recur_weekdays, recur_interval, last_completed_on FROM todos WHERE id = $1`, id,
	).Scan(&clearedWeekdays, &clearedInterval, &lastCompleted); err != nil {
		t.Fatalf("reading cleared recurrence: %v", err)
	}
	if clearedWeekdays != nil || clearedInterval != nil {
		t.Errorf("after clear: recur_weekdays=%v recur_interval=%v, want both NULL", clearedWeekdays, clearedInterval)
	}
	if lastCompleted != nil {
		t.Errorf("after clear: last_completed_on = %v, want NULL (invariant)", lastCompleted)
	}
}
