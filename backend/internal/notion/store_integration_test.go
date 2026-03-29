//go:build integration

package notion

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func setupStore(t *testing.T) *Store {
	t.Helper()
	testdb.Truncate(t, testPool, "notion_sources")
	return NewStore(testPool)
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T { return &v }

// minimalParams returns a CreateSourceParams with all required fields set.
// databaseID must be unique across concurrent tests.
func minimalParams(databaseID string) *CreateSourceParams {
	return &CreateSourceParams{
		DatabaseID:   databaseID,
		Name:         "Test Source",
		Description:  "Integration test source",
		SyncMode:     SyncModeFull,
		PropertyMap:  json.RawMessage(`{}`),
		PollInterval: "1 hour",
	}
}

// TestCreateSource_RoundTrip inserts a source and reads it back, verifying all fields.
func TestCreateSource_RoundTrip(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	p := &CreateSourceParams{
		DatabaseID:   "db-roundtrip-001",
		Name:         "My Database",
		Description:  "A test database",
		SyncMode:     SyncModeFull,
		PropertyMap:  json.RawMessage(`{"title":"Name"}`),
		PollInterval: "30 minutes",
	}

	created, err := s.CreateSource(ctx, p)
	if err != nil {
		t.Fatalf("CreateSource() error: %v", err)
	}

	if created.ID == uuid.Nil {
		t.Fatal("CreateSource() returned zero UUID")
	}

	got, err := s.Source(ctx, created.ID)
	if err != nil {
		t.Fatalf("Source(%s) error: %v", created.ID, err)
	}

	opts := cmp.Options{
		cmpopts.IgnoreFields(Source{}, "CreatedAt", "UpdatedAt", "LastSyncedAt", "PropertyMap"),
	}
	want := &Source{
		ID:           created.ID,
		DatabaseID:   "db-roundtrip-001",
		Name:         "My Database",
		Description:  "A test database",
		SyncMode:     SyncModeFull,
		PropertyMap:  json.RawMessage(`{"title":"Name"}`),
		PollInterval: "30 minutes",
		Enabled:      true, // default
	}

	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("Source() mismatch (-want +got):\n%s", diff)
	}

	// Compare PropertyMap as parsed JSON (PostgreSQL jsonb normalizes whitespace).
	var wantPM, gotPM map[string]any
	if err := json.Unmarshal([]byte(`{"title":"Name"}`), &wantPM); err != nil {
		t.Fatalf("unmarshaling want PropertyMap: %v", err)
	}
	if err := json.Unmarshal(got.PropertyMap, &gotPM); err != nil {
		t.Fatalf("unmarshaling got PropertyMap: %v", err)
	}
	if diff := cmp.Diff(wantPM, gotPM); diff != "" {
		t.Errorf("PropertyMap mismatch (-want +got):\n%s", diff)
	}
}

// TestCreateSource_DuplicateDatabaseID verifies ErrConflict on unique violation.
func TestCreateSource_DuplicateDatabaseID(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	p := minimalParams("db-duplicate-001")

	if _, err := s.CreateSource(ctx, p); err != nil {
		t.Fatalf("CreateSource() first insert error: %v", err)
	}

	_, err := s.CreateSource(ctx, p)
	if !errors.Is(err, ErrConflict) {
		t.Errorf("CreateSource() duplicate = %v, want ErrConflict", err)
	}
}

// TestSource_NotFound verifies ErrNotFound for a non-existent ID.
func TestSource_NotFound(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	_, err := s.Source(ctx, uuid.New())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Source(unknown) = %v, want ErrNotFound", err)
	}
}

// TestSources_Ordering verifies that Sources returns all rows newest-first.
func TestSources_Ordering(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	// Insert two sources in order.
	for _, dbID := range []string{"db-order-001", "db-order-002"} {
		if _, err := s.CreateSource(ctx, minimalParams(dbID)); err != nil {
			t.Fatalf("CreateSource(%q) error: %v", dbID, err)
		}
	}

	sources, err := s.Sources(ctx)
	if err != nil {
		t.Fatalf("Sources() error: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("Sources() count = %d, want 2", len(sources))
	}

	// ORDER BY created_at DESC — second inserted should appear first.
	if sources[0].DatabaseID != "db-order-002" {
		t.Errorf("Sources()[0].DatabaseID = %q, want %q", sources[0].DatabaseID, "db-order-002")
	}
	if sources[1].DatabaseID != "db-order-001" {
		t.Errorf("Sources()[1].DatabaseID = %q, want %q", sources[1].DatabaseID, "db-order-001")
	}
}

// TestSources_Empty verifies that Sources returns an empty (non-nil) slice.
func TestSources_Empty(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	sources, err := s.Sources(ctx)
	if err != nil {
		t.Fatalf("Sources() empty error: %v", err)
	}
	if sources == nil {
		t.Error("Sources() = nil, want empty slice")
	}
	if len(sources) != 0 {
		t.Errorf("Sources() count = %d, want 0", len(sources))
	}
}

// TestSourceByRole_Found verifies a role lookup returns the correct source.
func TestSourceByRole_Found(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	created, err := s.CreateSource(ctx, minimalParams("db-role-001"))
	if err != nil {
		t.Fatalf("CreateSource() error: %v", err)
	}

	if err := s.SetRole(ctx, created.ID, RoleProjects); err != nil {
		t.Fatalf("SetRole() error: %v", err)
	}

	src, err := s.SourceByRole(ctx, RoleProjects)
	if err != nil {
		t.Fatalf("SourceByRole(%q) error: %v", RoleProjects, err)
	}

	if src.ID != created.ID {
		t.Errorf("SourceByRole(%q).ID = %s, want %s", RoleProjects, src.ID, created.ID)
	}
	if src.Role == nil || *src.Role != RoleProjects {
		t.Errorf("SourceByRole(%q).Role = %v, want %q", RoleProjects, src.Role, RoleProjects)
	}
}

// TestSourceByRole_NotFound verifies ErrNotFound when no source has the role.
func TestSourceByRole_NotFound(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	_, err := s.SourceByRole(ctx, RoleTasks)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("SourceByRole(no match) = %v, want ErrNotFound", err)
	}
}

// TestSourceByRole_DisabledExcluded verifies that a disabled source is not returned by role.
func TestSourceByRole_DisabledExcluded(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	created, err := s.CreateSource(ctx, minimalParams("db-role-disabled-001"))
	if err != nil {
		t.Fatalf("CreateSource() error: %v", err)
	}
	if err := s.SetRole(ctx, created.ID, RoleBooks); err != nil {
		t.Fatalf("SetRole() error: %v", err)
	}

	// Disable the source; ToggleEnabled flips true → false.
	if _, err := s.ToggleEnabled(ctx, created.ID); err != nil {
		t.Fatalf("ToggleEnabled() error: %v", err)
	}

	_, err = s.SourceByRole(ctx, RoleBooks)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("SourceByRole(disabled source) = %v, want ErrNotFound", err)
	}
}

// TestDatabaseIDByRole_Found verifies the database_id is returned correctly.
func TestDatabaseIDByRole_Found(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	p := minimalParams("db-role-id-001")
	created, err := s.CreateSource(ctx, p)
	if err != nil {
		t.Fatalf("CreateSource() error: %v", err)
	}
	if err := s.SetRole(ctx, created.ID, RoleGoals); err != nil {
		t.Fatalf("SetRole() error: %v", err)
	}

	got, err := s.DatabaseIDByRole(ctx, RoleGoals)
	if err != nil {
		t.Fatalf("DatabaseIDByRole(%q) error: %v", RoleGoals, err)
	}
	if got != "db-role-id-001" {
		t.Errorf("DatabaseIDByRole(%q) = %q, want %q", RoleGoals, got, "db-role-id-001")
	}
}

// TestDatabaseIDByRole_NotFound verifies ErrNotFound when no source has the role.
func TestDatabaseIDByRole_NotFound(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	_, err := s.DatabaseIDByRole(ctx, RoleGoals)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("DatabaseIDByRole(no match) = %v, want ErrNotFound", err)
	}
}

// TestDeleteSource_Gone verifies a source is gone after deletion.
func TestDeleteSource_Gone(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	created, err := s.CreateSource(ctx, minimalParams("db-delete-001"))
	if err != nil {
		t.Fatalf("CreateSource() error: %v", err)
	}

	if err := s.DeleteSource(ctx, created.ID); err != nil {
		t.Fatalf("DeleteSource() error: %v", err)
	}

	// Read back should return ErrNotFound.
	_, err = s.Source(ctx, created.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Source(deleted) = %v, want ErrNotFound", err)
	}
}

// TestDeleteSource_NotFound verifies ErrNotFound on a non-existent ID.
func TestDeleteSource_NotFound(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	err := s.DeleteSource(ctx, uuid.New())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteSource(unknown) = %v, want ErrNotFound", err)
	}
}

// TestToggleEnabled_FlipsBothWays verifies the toggle inverts the enabled flag.
func TestToggleEnabled_FlipsBothWays(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	created, err := s.CreateSource(ctx, minimalParams("db-toggle-001"))
	if err != nil {
		t.Fatalf("CreateSource() error: %v", err)
	}
	if !created.Enabled {
		t.Fatalf("CreateSource() Enabled = false, want true (default)")
	}

	// true → false
	toggled, err := s.ToggleEnabled(ctx, created.ID)
	if err != nil {
		t.Fatalf("ToggleEnabled() first call error: %v", err)
	}
	if toggled.Enabled {
		t.Error("ToggleEnabled() first call Enabled = true, want false")
	}

	// false → true
	toggled, err = s.ToggleEnabled(ctx, created.ID)
	if err != nil {
		t.Fatalf("ToggleEnabled() second call error: %v", err)
	}
	if !toggled.Enabled {
		t.Error("ToggleEnabled() second call Enabled = false, want true")
	}
}

// TestToggleEnabled_NotFound verifies ErrNotFound for a non-existent ID.
func TestToggleEnabled_NotFound(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	_, err := s.ToggleEnabled(ctx, uuid.New())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("ToggleEnabled(unknown) = %v, want ErrNotFound", err)
	}
}

// TestUpdateSource_Fields verifies that partial update respects COALESCE semantics.
func TestUpdateSource_Fields(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	created, err := s.CreateSource(ctx, &CreateSourceParams{
		DatabaseID:   "db-update-001",
		Name:         "Original Name",
		Description:  "Original Desc",
		SyncMode:     SyncModeFull,
		PropertyMap:  json.RawMessage(`{}`),
		PollInterval: "1 hour",
	})
	if err != nil {
		t.Fatalf("CreateSource() error: %v", err)
	}

	updated, err := s.UpdateSource(ctx, created.ID, &UpdateSourceParams{
		Name: ptr("Updated Name"),
	})
	if err != nil {
		t.Fatalf("UpdateSource() error: %v", err)
	}

	if updated.Name != "Updated Name" {
		t.Errorf("UpdateSource().Name = %q, want %q", updated.Name, "Updated Name")
	}
	// Description should be unchanged (COALESCE keeps original).
	if updated.Description != "Original Desc" {
		t.Errorf("UpdateSource().Description = %q, want %q (unchanged)", updated.Description, "Original Desc")
	}
}

// TestUpdateSource_NotFound verifies ErrNotFound for a non-existent ID.
func TestUpdateSource_NotFound(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	_, err := s.UpdateSource(ctx, uuid.New(), &UpdateSourceParams{
		Name: ptr("Ghost"),
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateSource(unknown) = %v, want ErrNotFound", err)
	}
}

// TestSetRole_Atomic verifies that SetRole clears the role from the previous holder
// and assigns it to the new source in a single transaction.
func TestSetRole_Atomic(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	first, err := s.CreateSource(ctx, minimalParams("db-setrole-first"))
	if err != nil {
		t.Fatalf("CreateSource(first) error: %v", err)
	}
	second, err := s.CreateSource(ctx, minimalParams("db-setrole-second"))
	if err != nil {
		t.Fatalf("CreateSource(second) error: %v", err)
	}

	// Assign role to first.
	if err := s.SetRole(ctx, first.ID, RoleProjects); err != nil {
		t.Fatalf("SetRole(first) error: %v", err)
	}

	// Re-assign role to second — first should lose it.
	if err := s.SetRole(ctx, second.ID, RoleProjects); err != nil {
		t.Fatalf("SetRole(second) error: %v", err)
	}

	// Verify second now holds the role.
	got, err := s.SourceByRole(ctx, RoleProjects)
	if err != nil {
		t.Fatalf("SourceByRole() after re-assign error: %v", err)
	}
	if got.ID != second.ID {
		t.Errorf("SourceByRole().ID = %s, want %s (second)", got.ID, second.ID)
	}

	// Verify first no longer has the role (read its current state).
	firstNow, err := s.Source(ctx, first.ID)
	if err != nil {
		t.Fatalf("Source(first) after re-assign error: %v", err)
	}
	if firstNow.Role != nil {
		t.Errorf("Source(first).Role = %v, want nil (cleared)", firstNow.Role)
	}
}

// TestSetRole_NotFound verifies ErrNotFound when the target source does not exist.
func TestSetRole_NotFound(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	err := s.SetRole(ctx, uuid.New(), RoleGoals)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("SetRole(unknown id) = %v, want ErrNotFound", err)
	}
}

// TestClearSourceRole_OK verifies that the role is removed from a specific source.
func TestClearSourceRole_OK(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	created, err := s.CreateSource(ctx, minimalParams("db-clearrole-001"))
	if err != nil {
		t.Fatalf("CreateSource() error: %v", err)
	}
	if err := s.SetRole(ctx, created.ID, RoleTasks); err != nil {
		t.Fatalf("SetRole() error: %v", err)
	}

	if err := s.ClearSourceRole(ctx, created.ID); err != nil {
		t.Fatalf("ClearSourceRole() error: %v", err)
	}

	src, err := s.Source(ctx, created.ID)
	if err != nil {
		t.Fatalf("Source() after clear error: %v", err)
	}
	if src.Role != nil {
		t.Errorf("Source().Role = %v, want nil after ClearSourceRole", src.Role)
	}
}

// TestClearSourceRole_NotFound verifies ErrNotFound for a non-existent ID.
func TestClearSourceRole_NotFound(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	err := s.ClearSourceRole(ctx, uuid.New())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("ClearSourceRole(unknown) = %v, want ErrNotFound", err)
	}
}

// TestUpdateLastSynced_TimestampUpdates verifies the last_synced_at is set after a call.
func TestUpdateLastSynced_TimestampUpdates(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	created, err := s.CreateSource(ctx, minimalParams("db-lastsynced-001"))
	if err != nil {
		t.Fatalf("CreateSource() error: %v", err)
	}
	if created.LastSyncedAt != nil {
		t.Fatal("CreateSource() LastSyncedAt should be nil before first sync")
	}

	if err := s.UpdateLastSynced(ctx, created.ID); err != nil {
		t.Fatalf("UpdateLastSynced() error: %v", err)
	}

	updated, err := s.Source(ctx, created.ID)
	if err != nil {
		t.Fatalf("Source() after sync error: %v", err)
	}
	if updated.LastSyncedAt == nil {
		t.Error("Source().LastSyncedAt = nil, want non-nil after UpdateLastSynced")
	}
}

// TestSourceByDatabaseID_Found verifies lookup by Notion database_id.
func TestSourceByDatabaseID_Found(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	created, err := s.CreateSource(ctx, minimalParams("db-bydbid-001"))
	if err != nil {
		t.Fatalf("CreateSource() error: %v", err)
	}

	got, err := s.SourceByDatabaseID(ctx, "db-bydbid-001")
	if err != nil {
		t.Fatalf("SourceByDatabaseID() error: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("SourceByDatabaseID().ID = %s, want %s", got.ID, created.ID)
	}
}

// TestSourceByDatabaseID_NotFound verifies ErrNotFound for an unknown database_id.
func TestSourceByDatabaseID_NotFound(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	_, err := s.SourceByDatabaseID(ctx, "db-does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("SourceByDatabaseID(unknown) = %v, want ErrNotFound", err)
	}
}

// TestConcurrentInserts verifies that concurrent inserts do not race or corrupt data.
func TestConcurrentInserts(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	const n = 10
	errs := make([]error, n)
	var wg sync.WaitGroup

	for i := range n {
		wg.Go(func() {
			_, errs[i] = s.CreateSource(ctx, minimalParams(
				// unique database_id per goroutine
				"db-concurrent-"+string(rune('0'+i)),
			))
		})
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d CreateSource() error: %v", i, err)
		}
	}

	sources, err := s.Sources(ctx)
	if err != nil {
		t.Fatalf("Sources() after concurrent inserts error: %v", err)
	}
	if len(sources) != n {
		t.Errorf("Sources() count = %d, want %d after concurrent inserts", len(sources), n)
	}
}
