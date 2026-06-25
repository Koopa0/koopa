// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// Integration coverage for the admin project detail endpoint. The handler
// aggregates data from four sources (project row, goal, todos, activity,
// content) and had to exist for the ProjectInspector frontend
// to stop 404'ing. This suite pins the wire contract so a future refactor
// cannot silently drop a field.
//
// Run with:
//
//	go test -tags=integration ./internal/project/...
//
// Lives in package project_test (not project) to keep test seeding
// flexible — the raw-SQL goal inserts below bypass the goal package
// entirely, and an external test package leaves room to add goal-store
// assertions later without re-creating the former project→goal handler
// dependency that was eliminated once the breadcrumb moved into the
// ProjectDetailByID SQL JOIN.
package project_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/activity"
	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/project"
	"github.com/Koopa0/koopa/internal/testdb"
	"github.com/Koopa0/koopa/internal/todo"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.NewPool()
	testPool = pool

	// activity_events.actor has an FK onto agents; without seeded agent
	// rows any write that fires the audit trigger (goal/project/todo
	// inserts included) fails with 23503. Reconcile the builtin registry
	// once per suite, same as cmd/mcp/main.go does at startup.
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

// newDetailHandler wires a fully-loaded project.Handler using the shared
// test pool. Mirrors the cmd/app/main.go wiring so the endpoint under
// test sees the same reader set a real request would.
func newDetailHandler(t *testing.T) *project.Handler {
	t.Helper()
	logger := slog.Default()
	return project.NewHandler(
		project.NewStore(testPool),
		todo.NewStore(testPool),
		activity.NewStore(testPool),
		content.NewStore(testPool),
		logger,
	)
}

// callDetail runs the Detail handler against a fabricated request and
// decodes the response body into the pinned wire envelope + Detail shape.
// Returns the decoded detail plus the HTTP status so assertions stay
// explicit about 200 vs 404 branches.
func callDetail(t *testing.T, h *project.Handler, id string) (detail project.Detail, status int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/projects/"+id, http.NoBody)
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	h.Detail(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return project.Detail{}, resp.StatusCode
	}
	var envelope struct {
		Data project.Detail `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decoding detail body: %v", err)
	}
	return envelope.Data, resp.StatusCode
}

// seedBareProject inserts a minimal project row and returns its id. Used
// by tests that need a project without todos / activity.
func seedBareProject(t *testing.T, slug, title string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO projects (slug, title, description, status)
		 VALUES ($1, $2, $3, 'in_progress') RETURNING id`,
		slug, title, "Test project for detail endpoint",
	).Scan(&id); err != nil {
		t.Fatalf("seeding project: %v", err)
	}
	return id
}

// seedProjectWithStatus inserts a project in the given lifecycle status,
// stamping created_by with a registered agent so a proposed row carries the
// provenance propose_project would. Returns the id.
func seedProjectWithStatus(t *testing.T, slug, title, status string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO projects (slug, title, description, status, created_by)
		 VALUES ($1, $2, '', $3::project_status, 'koopa0-dev') RETURNING id`,
		slug, title, status,
	).Scan(&id); err != nil {
		t.Fatalf("seeding %s project: %v", status, err)
	}
	return id
}

// truncate resets every table the Detail endpoint reads from so each test
// runs against a clean slate without leaking seed data from earlier cases.
func truncate(t *testing.T) {
	t.Helper()
	_, err := testPool.Exec(t.Context(), `
		TRUNCATE contents, todos, activity_events,
		         projects, goals
		RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// TestIntegration_Detail_ProjectNotFound is the 404 branch: path parses
// but no row exists. The handler must NOT 500 or leak SQL errors.
func TestIntegration_Detail_ProjectNotFound(t *testing.T) {
	truncate(t)
	h := newDetailHandler(t)

	_, status := callDetail(t, h, uuid.New().String())
	if status != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for unknown project", status)
	}
}

// TestIntegration_Detail_InvalidIDReturns400 — non-UUID path param must
// produce a 400, not a 500 from uuid.Parse.
func TestIntegration_Detail_InvalidIDReturns400(t *testing.T) {
	truncate(t)
	h := newDetailHandler(t)

	_, status := callDetail(t, h, "not-a-uuid")
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for invalid uuid", status)
	}
}

// TestIntegration_Detail_BareProject is the minimal happy path — a
// project row exists but has no goal, no todos, no activity, no related
// content. The handler must still return 200 with all aggregate fields
// rendered as empty collections (never null).
func TestIntegration_Detail_BareProject(t *testing.T) {
	truncate(t)
	id := seedBareProject(t, "test-bare", "Bare Project")
	h := newDetailHandler(t)

	detail, status := callDetail(t, h, id.String())
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	if detail.ID != id {
		t.Errorf("id = %s, want %s", detail.ID, id)
	}
	if detail.Title != "Bare Project" {
		t.Errorf("title = %q, want %q", detail.Title, "Bare Project")
	}
	if detail.Slug != "test-bare" {
		t.Errorf("slug = %q, want %q", detail.Slug, "test-bare")
	}
	if detail.GoalBreadcrumb != nil {
		t.Error("goal_breadcrumb should be nil when project has no goal")
	}
	if detail.RecentActivity == nil {
		t.Error("recent_activity should be [] not nil")
	}
	if detail.RelatedContent == nil {
		t.Error("related_content should be [] not nil")
	}
}

// TestIntegration_Detail_FullAggregate seeds a project with every
// aggregate source populated. Verifies each slice carries across the
// wire contract, confirming the frontend inspector will receive a
// complete ProjectDetail shape.
func TestIntegration_Detail_FullAggregate(t *testing.T) {
	truncate(t)

	// Goal for the breadcrumb.
	var goalID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title, status) VALUES ('Test Goal', 'in_progress') RETURNING id`,
	).Scan(&goalID); err != nil {
		t.Fatalf("seeding goal: %v", err)
	}

	// Project wired to the goal.
	var projectID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO projects (slug, title, description, status, goal_id)
		 VALUES ($1, $2, 'desc', 'in_progress', $3) RETURNING id`,
		"test-full", "Full Project", goalID,
	).Scan(&projectID); err != nil {
		t.Fatalf("seeding project: %v", err)
	}

	// Todos across four states to exercise the grouping. The schema
	// check chk_todo_completed_at_consistency requires completed_at on
	// rows in state='done', so seed those with now().
	for _, tc := range []struct{ title, state string }{
		{"active work", "in_progress"},
		{"queued work", "todo"},
		{"someday/maybe", "someday"},
	} {
		if _, err := testPool.Exec(t.Context(),
			`INSERT INTO todos (title, state, project_id) VALUES ($1, $2::todo_state, $3)`,
			tc.title, tc.state, projectID,
		); err != nil {
			t.Fatalf("seeding todo (%s): %v", tc.state, err)
		}
	}
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO todos (title, state, project_id, completed_at)
		 VALUES ('finished work', 'done'::todo_state, $1, now())`,
		projectID,
	); err != nil {
		t.Fatalf("seeding done todo: %v", err)
	}

	// Activity event scoped via slug. actor is NOT NULL and FKs onto
	// agents — use planner, which the builtin registry sync populates.
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO activity_events (entity_type, change_kind, entity_id, project_id, entity_title, actor, occurred_at)
		 VALUES ('todo', 'created', $1, $2, 'seeded activity', 'planner', now())`,
		uuid.New(), projectID,
	); err != nil {
		t.Fatalf("seeding activity event: %v", err)
	}

	// Related content row.
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO contents (slug, title, body, excerpt, type, status, project_id)
		 VALUES ($1, $2, 'body', 'excerpt', 'article', 'draft', $3)`,
		"test-article", "Test Article", projectID,
	); err != nil {
		t.Fatalf("seeding content: %v", err)
	}

	h := newDetailHandler(t)
	detail, status := callDetail(t, h, projectID.String())
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	// Goal breadcrumb.
	if detail.GoalBreadcrumb == nil {
		t.Fatal("goal_breadcrumb should be present")
	}
	if detail.GoalBreadcrumb.GoalID != goalID {
		t.Errorf("goal_breadcrumb.goal_id = %s, want %s", detail.GoalBreadcrumb.GoalID, goalID)
	}
	if detail.GoalBreadcrumb.GoalTitle != "Test Goal" {
		t.Errorf("goal_breadcrumb.goal_title = %q, want %q", detail.GoalBreadcrumb.GoalTitle, "Test Goal")
	}

	// Activity bubbled up. Exact count depends on how many audit
	// triggers fire for the surrounding seed INSERTs (project, todos,
	// content each emit their own audit row), so pin the contract at
	// "at least one" — the point is that the aggregate is populated
	// and sortable, not that we counted every trigger.
	if len(detail.RecentActivity) == 0 {
		t.Error("recent_activity should have at least one event after seeding")
	}

	// Related content surfaced.
	if len(detail.RelatedContent) != 1 {
		t.Fatalf("related_content length = %d, want 1", len(detail.RelatedContent))
	}
	if detail.RelatedContent[0].Slug != "test-article" {
		t.Errorf("related_content[0].slug = %q, want 'test-article'", detail.RelatedContent[0].Slug)
	}

	// TodosByState must be present (shape verified via JSON round-trip).
	if detail.TodosByState == nil {
		t.Error("todos_by_state should be populated when project has todos")
	}
}

// TestIntegration_Project_InvalidInput verifies that values the database
// rejects on the project write paths surface as project.ErrInvalidInput —
// which the handler maps to HTTP 400 — instead of a wrapped error rendered as
// an opaque 500. It covers the three reachable classes: a foreign key pointing
// at a non-existent goal_id (23503), a malformed slug (chk_project_slug_format
// 23514), and an out-of-range expected_cadence (the cadence CHECK 23514).
func TestIntegration_Project_InvalidInput(t *testing.T) {
	truncate(t)
	store := project.NewStore(testPool)
	ctx := t.Context()

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create with non-existent goal_id (foreign key 23503)",
			run: func() error {
				missing := uuid.New()
				_, err := store.CreateProject(ctx, &project.CreateParams{
					Slug:   "fk-orphan",
					Title:  "FK Orphan",
					Status: project.StatusInProgress,
					GoalID: &missing,
				})
				return err
			},
		},
		{
			name: "create with malformed slug (chk_project_slug_format 23514)",
			run: func() error {
				_, err := store.CreateProject(ctx, &project.CreateParams{
					Slug:   "Not A Valid Slug!",
					Title:  "Bad Slug",
					Status: project.StatusInProgress,
				})
				return err
			},
		},
		{
			name: "update status with invalid expected_cadence (cadence CHECK 23514)",
			run: func() error {
				id := seedBareProject(t, "cadence-target", "Cadence Target")
				bad := "fortnightly"
				_, err := store.UpdateStatus(ctx, id, project.StatusInProgress, nil, &bad)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, project.ErrInvalidInput) {
				t.Fatalf("err = %v, want project.ErrInvalidInput", err)
			}
		})
	}
}

// TestIntegration_ProposedProject_InertButResolvable pins the propose_project
// contract: a proposed project is excluded from the admin project list (the
// explicit status guard) yet remains resolvable by slug so capture_inbox can
// link a todo to it before the owner activates it.
func TestIntegration_ProposedProject_InertButResolvable(t *testing.T) {
	truncate(t)
	store := project.NewStore(testPool)
	ctx := t.Context()

	proposedID := seedProjectWithStatus(t, "ghost-tool", "Ghost Tool", "proposed")
	realID := seedProjectWithStatus(t, "real-tool", "Real Tool", "in_progress")

	// Admin list: real present, proposed absent.
	admin, err := store.Projects(ctx)
	if err != nil {
		t.Fatalf("Projects: %v", err)
	}
	if containsProjectID(admin, proposedID) {
		t.Errorf("admin project list includes proposed project %s, want excluded", proposedID)
	}
	if !containsProjectID(admin, realID) {
		t.Errorf("admin project list missing real project %s", realID)
	}

	// Resolver: the proposed project is still resolvable by slug for capture.
	got, err := store.ProjectBySlug(ctx, "ghost-tool")
	if err != nil {
		t.Fatalf("ProjectBySlug(ghost-tool): %v (a proposed project must resolve for capture_inbox)", err)
	}
	if got.ID != proposedID {
		t.Errorf("ProjectBySlug(ghost-tool).ID = %s, want %s", got.ID, proposedID)
	}
	if got.Status != project.StatusProposed {
		t.Errorf("ProjectBySlug(ghost-tool).Status = %q, want %q", got.Status, project.StatusProposed)
	}
}

// containsProjectID reports whether any project in the slice has the given id.
func containsProjectID(projects []project.Project, id uuid.UUID) bool {
	for i := range projects {
		if projects[i].ID == id {
			return true
		}
	}
	return false
}

// serveProject runs an admin request through ActorMiddleware (actor="human",
// the admin-write convention) into the given handler, mirroring the production
// adminMid chain that binds the per-request actor tx the audit triggers read.
func serveProject(t *testing.T, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	mid := api.ActorMiddleware(testPool, "human", slog.Default())
	rec := httptest.NewRecorder()
	mid(h).ServeHTTP(rec, req)
	return rec
}

// activateReq / rejectReq build the commitment triage requests with the path id
// pre-bound (the handlers read r.PathValue("id")).
func activateReq(t *testing.T, id uuid.UUID) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/commitment/projects/"+id.String()+"/activate", nil)
	req.SetPathValue("id", id.String())
	return req
}

func rejectReq(t *testing.T, id uuid.UUID) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/commitment/projects/"+id.String()+"/proposed", nil)
	req.SetPathValue("id", id.String())
	return req
}

// TestIntegration_Project_ActivateProject drives POST /projects/{id}/activate:
// a proposed project flips to in_progress (200); a real project is 409
// NOT_PROPOSED; a missing project is 404.
func TestIntegration_Project_ActivateProject(t *testing.T) {
	truncate(t)
	h := newDetailHandler(t)

	proposedID := seedProjectWithStatus(t, "activate-me", "Activate Me", "proposed")
	rec := serveProject(t, h.ActivateProject, activateReq(t, proposedID))
	if rec.Code != http.StatusOK {
		t.Fatalf("activate proposed status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var status string
	if err := testPool.QueryRow(t.Context(), `SELECT status FROM projects WHERE id=$1`, proposedID).Scan(&status); err != nil {
		t.Fatalf("reading activated project: %v", err)
	}
	if status != "in_progress" {
		t.Errorf("activated status = %q, want in_progress", status)
	}

	// A real (already in_progress) project is not a proposed draft → 409.
	realID := seedProjectWithStatus(t, "already-real", "Already Real", "in_progress")
	if rec := serveProject(t, h.ActivateProject, activateReq(t, realID)); rec.Code != http.StatusConflict {
		t.Errorf("activate real project status = %d, want 409 NOT_PROPOSED", rec.Code)
	}

	// A missing project is 404.
	if rec := serveProject(t, h.ActivateProject, activateReq(t, uuid.New())); rec.Code != http.StatusNotFound {
		t.Errorf("activate missing project status = %d, want 404", rec.Code)
	}
}

// TestIntegration_Project_RejectProject drives DELETE /projects/{id}/proposed:
// a proposed project is hard-deleted (204); a real project is 409 NOT_PROPOSED
// and survives.
func TestIntegration_Project_RejectProject(t *testing.T) {
	truncate(t)
	h := newDetailHandler(t)

	proposedID := seedProjectWithStatus(t, "reject-me", "Reject Me", "proposed")
	if rec := serveProject(t, h.RejectProject, rejectReq(t, proposedID)); rec.Code != http.StatusNoContent {
		t.Fatalf("reject proposed status = %d, want 204 (body=%s)", rec.Code, rec.Body.String())
	}
	var count int
	if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM projects WHERE id=$1`, proposedID).Scan(&count); err != nil {
		t.Fatalf("counting rejected project: %v", err)
	}
	if count != 0 {
		t.Errorf("rejected project still present (count=%d), want hard-deleted", count)
	}

	// A real project rejected through this path is 409 and survives untouched.
	realID := seedProjectWithStatus(t, "keep-me", "Keep Me", "in_progress")
	if rec := serveProject(t, h.RejectProject, rejectReq(t, realID)); rec.Code != http.StatusConflict {
		t.Errorf("reject real project status = %d, want 409 NOT_PROPOSED", rec.Code)
	}
	var realStatus string
	if err := testPool.QueryRow(t.Context(), `SELECT status FROM projects WHERE id=$1`, realID).Scan(&realStatus); err != nil {
		t.Fatalf("real project must survive a rejected reject: %v", err)
	}
	if realStatus != "in_progress" {
		t.Errorf("real project status after rejected reject = %q, want in_progress", realStatus)
	}
}

// TestIntegration_Project_ProposedProjectsTriage covers the store triage reads:
// ProposedProjects lists only proposed rows (with rationale surfaced), and
// ProposedProjectsCount counts them; non-proposed projects are excluded.
func TestIntegration_Project_ProposedProjectsTriage(t *testing.T) {
	truncate(t)
	store := project.NewStore(testPool)
	ctx := t.Context()

	const rationale = "Terminal entry point keeps coming up."
	var proposedID uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO projects (slug, title, description, status, created_by, proposal_rationale)
		 VALUES ('triage-one', 'Triage One', '', 'proposed', 'koopa0-dev', $1) RETURNING id`,
		rationale,
	).Scan(&proposedID); err != nil {
		t.Fatalf("seeding proposed project: %v", err)
	}
	_ = seedProjectWithStatus(t, "triage-real", "Triage Real", "in_progress")

	list, err := store.ProposedProjects(ctx)
	if err != nil {
		t.Fatalf("ProposedProjects: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ProposedProjects len = %d, want 1 (only the proposed row)", len(list))
	}
	if list[0].ID != proposedID {
		t.Errorf("ProposedProjects[0].ID = %s, want %s", list[0].ID, proposedID)
	}
	if list[0].ProposalRationale == nil || *list[0].ProposalRationale != rationale {
		t.Errorf("ProposedProjects[0].ProposalRationale = %v, want %q", list[0].ProposalRationale, rationale)
	}

	count, err := store.ProposedProjectsCount(ctx)
	if err != nil {
		t.Fatalf("ProposedProjectsCount: %v", err)
	}
	if count != 1 {
		t.Errorf("ProposedProjectsCount = %d, want 1", count)
	}
}
