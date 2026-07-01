// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go drives agent.SyncToTable against a real PostgreSQL
// (testcontainers), proving the batched UpsertAll/RetireAll round trips
// reconcile the agents table the same way the old per-row loop did:
// fresh registration upserts as active, removing an entry from the
// registry retires its row, an already-retired row is idempotent, and
// re-adding a retired entry flips it back to active.
//
// Run with:
//
//	go test -count=1 -tags=integration ./internal/agent/...
package agent_test

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.NewPool()
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func truncate(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(), `TRUNCATE agents CASCADE`); err != nil {
		t.Fatalf("truncating agents: %v", err)
	}
}

// agentRow is the subset of the agents table this test asserts on. It
// deliberately includes display_name/platform (not just status) because the
// refactor under test zips four parallel arrays via
// ROWS FROM(unnest(names), unnest(display_names), unnest(platforms),
// unnest(descriptions)) — a column-order bug there would write plausible
// but wrong data for a row, not error, so status alone can't catch it.
type agentRow struct {
	Status      string
	DisplayName string
	Platform    string
	RetiredAt   *time.Time
}

func readAgent(t *testing.T, name agent.Name) agentRow {
	t.Helper()
	var r agentRow
	if err := testPool.QueryRow(t.Context(),
		`SELECT status, display_name, platform, retired_at FROM agents WHERE name = $1`, string(name),
	).Scan(&r.Status, &r.DisplayName, &r.Platform, &r.RetiredAt); err != nil {
		t.Fatalf("reading agent %s: %v", name, err)
	}
	return r
}

// TestIntegration_SyncToTable_UpsertRetireCycle drives a full reconcile
// cycle through the batched store methods: register two agents, drop one
// from the registry, re-run (idempotent retire), then re-add it.
func TestIntegration_SyncToTable_UpsertRetireCycle(t *testing.T) {
	truncate(t)
	store := agent.NewStore(testPool)
	logger := slog.Default()

	alice := agent.Agent{Name: "alice", DisplayName: "Alice", Platform: "human", Description: "test agent"}
	bob := agent.Agent{Name: "bob", DisplayName: "Bob", Platform: "codex", Description: "test agent"}

	// Round 1: both registered, fresh DB. Asserts display_name/platform per
	// row, not just status — the thing a transposed unnest() zip would get
	// wrong without erroring.
	reg := agent.NewRegistry([]agent.Agent{alice, bob})
	out, err := agent.SyncToTable(t.Context(), reg, store, nil, logger)
	if err != nil {
		t.Fatalf("SyncToTable (both registered): %v", err)
	}
	if diff := cmp.Diff(agent.SyncResult{Active: 2}, out); diff != "" {
		t.Errorf("round 1 result mismatch (-want +got):\n%s", diff)
	}
	wantAlice := agentRow{Status: "active", DisplayName: "Alice", Platform: "human"}
	if diff := cmp.Diff(wantAlice, readAgent(t, "alice")); diff != "" {
		t.Errorf("alice row mismatch (-want +got):\n%s", diff)
	}
	wantBob := agentRow{Status: "active", DisplayName: "Bob", Platform: "codex"}
	if diff := cmp.Diff(wantBob, readAgent(t, "bob")); diff != "" {
		t.Errorf("bob row mismatch (-want +got):\n%s", diff)
	}

	// Round 2: bob dropped from the registry — must retire.
	reg2 := agent.NewRegistry([]agent.Agent{alice})
	out2, err := agent.SyncToTable(t.Context(), reg2, store, nil, logger)
	if err != nil {
		t.Fatalf("SyncToTable (bob dropped): %v", err)
	}
	if diff := cmp.Diff(agent.SyncResult{Active: 1, Retired: 1}, out2); diff != "" {
		t.Errorf("round 2 result mismatch (-want +got):\n%s", diff)
	}
	bobRetired := readAgent(t, "bob")
	if bobRetired.Status != "retired" {
		t.Errorf("bob status = %q, want retired", bobRetired.Status)
	}
	if bobRetired.RetiredAt == nil {
		t.Fatal("bob retired_at is nil, want a timestamp")
	}
	if diff := cmp.Diff(agentRow{Status: "active", DisplayName: "Alice", Platform: "human"}, readAgent(t, "alice")); diff != "" {
		t.Errorf("alice row mismatch after bob's retirement (-want +got):\n%s", diff)
	}

	// Round 3: same registry again — bob's retirement must be idempotent,
	// not re-processed as a new retirement, and retired_at must be
	// preserved (COALESCE), not re-stamped to a later time.
	out3, err := agent.SyncToTable(t.Context(), reg2, store, nil, logger)
	if err != nil {
		t.Fatalf("SyncToTable (idempotent retire): %v", err)
	}
	if diff := cmp.Diff(agent.SyncResult{Active: 1, AlreadyRetired: 1}, out3); diff != "" {
		t.Errorf("round 3 result mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(bobRetired, readAgent(t, "bob"), cmpopts.EquateApproxTime(0)); diff != "" {
		t.Errorf("bob row changed on idempotent retire (-want +got):\n%s", diff)
	}

	// Round 4: bob re-added — ON CONFLICT must clear the prior retirement.
	out4, err := agent.SyncToTable(t.Context(), reg, store, nil, logger)
	if err != nil {
		t.Fatalf("SyncToTable (bob re-added): %v", err)
	}
	if diff := cmp.Diff(agent.SyncResult{Active: 2}, out4); diff != "" {
		t.Errorf("round 4 result mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(agentRow{Status: "active", DisplayName: "Bob", Platform: "codex"}, readAgent(t, "bob")); diff != "" {
		t.Errorf("bob row mismatch after re-add (-want +got):\n%s", diff)
	}
}
