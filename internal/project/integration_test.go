//go:build integration

// Integration coverage for the admin project detail endpoint. The handler
// aggregates data from five sources (project row, profile, goal, todos,
// activity, content) and had to exist for the ProjectInspector frontend
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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/activity"
	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/project"
	"github.com/Koopa0/koopa/internal/testdb"
	"github.com/Koopa0/koopa/internal/todo"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// activity_events.actor has an FK onto agents; without seeded agent
	// rows any write that fires the audit trigger (goal/project/todo
	// inserts included) fails with 23503. Reconcile the builtin registry
	// once per suite, same as cmd/mcp/main.go does at startup.
	registry := agent.NewBuiltinRegistry()
	if _, err := agent.SyncToTable(context.Background(), registry, agent.NewStore(pool), slog.Default()); err != nil {
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
func callDetail(t *testing.T, h *project.Handler, id string) (project.Detail, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/projects/"+id, nil)
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
// by tests that need a project without a profile / tasks / activity.
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

// truncate resets every table the Detail endpoint reads from so each test
// runs against a clean slate without leaking seed data from earlier cases.
func truncate(t *testing.T) {
	t.Helper()
	_, err := testPool.Exec(t.Context(), `
		TRUNCATE contents, todos, activity_events,
		         project_profiles, projects, goals
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
// project row exists but has no profile, no goal, no tasks, no activity,
// no related content. The handler must still return 200 with all
// aggregate fields rendered as empty collections (never null) and
// nullable string fields as nil.
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
	if detail.Problem != nil || detail.Solution != nil || detail.Architecture != nil {
		t.Error("problem/solution/architecture should be nil when profile absent")
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

	// Profile — case-study fields are the only reason the detail
	// endpoint surfaces problem/solution/architecture.
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO project_profiles (project_id, problem, solution, architecture)
		 VALUES ($1, 'prob', 'soln', 'arch')`,
		projectID,
	); err != nil {
		t.Fatalf("seeding profile: %v", err)
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
	// agents — use hq, which the builtin registry sync populates.
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO activity_events (entity_type, change_kind, entity_id, project_id, entity_title, actor, occurred_at)
		 VALUES ('todo', 'created', $1, $2, 'seeded activity', 'hq', now())`,
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

	// Profile fields — the inspector's main header content.
	if detail.Problem == nil || *detail.Problem != "prob" {
		t.Errorf("problem = %v, want 'prob'", detail.Problem)
	}
	if detail.Solution == nil || *detail.Solution != "soln" {
		t.Errorf("solution = %v, want 'soln'", detail.Solution)
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

// TestIntegration_ProjectArchive_TogglesProfilePublic exercises the archive
// coupling: archiving a project must demote its project_profile from
// public display so archived work stays off the public portfolio. The
// coupling used to live in the archive_project_profile() trigger; it now
// lives in project.Store.UpdateStatus (per .claude/rules/postgres-
// patterns.md — no business logic in triggers). Going through the Go
// store here is the point — a raw UPDATE would silently skip the demote
// and that is the guarantee we want the test to fail on.
// Scenario: seed a project (status=in_progress) + project_profile
// (is_public=true, featured=true) → store.UpdateStatus(archived) →
// assert profile.is_public and profile.featured are now both false.
func TestIntegration_ProjectArchive_TogglesProfilePublic(t *testing.T) {
	truncate(t)

	var projectID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO projects (slug, title, description, status)
		 VALUES ('archive-coupling', 'Archive Coupling Fixture', 'fixture', 'in_progress')
		 RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("seeding project: %v", err)
	}

	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO project_profiles (project_id, is_public, featured)
		 VALUES ($1, true, true)`, projectID,
	); err != nil {
		t.Fatalf("seeding project_profile: %v", err)
	}

	// Precondition: the profile starts public + featured.
	var preIsPublic, preFeatured bool
	if err := testPool.QueryRow(t.Context(),
		`SELECT is_public, featured FROM project_profiles WHERE project_id = $1`, projectID,
	).Scan(&preIsPublic, &preFeatured); err != nil {
		t.Fatalf("reading profile pre-archive: %v", err)
	}
	if !preIsPublic || !preFeatured {
		t.Fatalf("pre-archive profile state = (is_public=%v, featured=%v), want both true",
			preIsPublic, preFeatured)
	}

	// Archive the project via the Go store — the path that owns the
	// coupling now.
	store := project.NewStore(testPool)
	if _, err := store.UpdateStatus(t.Context(), projectID, project.StatusArchived, nil, nil); err != nil {
		t.Fatalf("store.UpdateStatus(archived): %v", err)
	}

	// Post-update: is_public and featured must both have flipped to
	// false. A regression in project.Store.UpdateStatus or a missing
	// DemoteProjectProfileOnArchive call shows up here.
	var postIsPublic, postFeatured bool
	if err := testPool.QueryRow(t.Context(),
		`SELECT is_public, featured FROM project_profiles WHERE project_id = $1`, projectID,
	).Scan(&postIsPublic, &postFeatured); err != nil {
		t.Fatalf("reading profile post-archive: %v", err)
	}
	if postIsPublic {
		t.Error("profile.is_public = true after archive, want false (archive coupling regression)")
	}
	if postFeatured {
		t.Error("profile.featured = true after archive, want false (archive coupling regression)")
	}
}
