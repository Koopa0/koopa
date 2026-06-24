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

// TestIntegration_Todo_List_SingleStateFilter pins the backward-compatible
// single-value state filter and the created_by projection: a list row must
// carry the creator identity, not serialize "".
func TestIntegration_Todo_List_SingleStateFilter(t *testing.T) {
	truncate(t)
	h := newHandler()

	someday := seedTodo(t, "Someday item", "someday", "planner")
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
	if env.Data[0].CreatedBy != "planner" {
		t.Errorf("created_by = %q, want %q (list projection must carry the creator)", env.Data[0].CreatedBy, "planner")
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
// resolve_task added the terminal states archived/dismissed, but the morning
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
