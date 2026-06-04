// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles the testcontainers-backed tests for the research
// package: the report corpus write path and fan-out assignment fulfillment.
//
// Run with:
//
//	go test -tags=integration ./internal/research/...
package research

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool
	// Seed the agents table so produced_by / assigned_to / assigned_by FKs
	// resolve, the same way cmd/mcp/main.go reconciles the registry at startup.
	registry := agent.NewBuiltinRegistry()
	if _, err := agent.SyncToTable(context.Background(), registry, agent.NewStore(pool), nil, slog.Default()); err != nil {
		cleanup()
		log.Fatalf("research test: sync agents: %v", err)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// reset clears the report-lane tables before each test (the container is shared
// across the package via TestMain).
func reset(t *testing.T) {
	t.Helper()
	testdb.Truncate(t, testPool, "reports", "research_assignments")
}

func TestIntegration_CreateReport_Defaults(t *testing.T) {
	reset(t)
	store := NewStore(testPool)
	ctx := t.Context()

	r, err := store.CreateReport(ctx, CreateReportParams{
		Title:      "DDIA partitioning notes",
		Body:       "consistent hashing vs key-range sharding",
		ProducedBy: "research-lab",
	})
	if err != nil {
		t.Fatalf("CreateReport: %v", err)
	}
	if r.TrustStatus != TrustLow {
		t.Errorf("CreateReport trust = %q, want %q (reports are born low_trust)", r.TrustStatus, TrustLow)
	}
	if r.OriginAssignmentID != nil {
		t.Errorf("CreateReport origin = %v, want nil (standalone report)", r.OriginAssignmentID)
	}
	if r.ProducedBy != "research-lab" {
		t.Errorf("CreateReport produced_by = %q, want %q", r.ProducedBy, "research-lab")
	}

	got, err := store.Report(ctx, r.ID)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if diff := cmp.Diff(r, got); diff != "" {
		t.Errorf("Report round-trip mismatch (-create +get):\n%s", diff)
	}
}

func TestIntegration_CreateReport_RequiresKnownAgent(t *testing.T) {
	reset(t)
	store := NewStore(testPool)

	_, err := store.CreateReport(t.Context(), CreateReportParams{
		Title:      "orphan report",
		ProducedBy: "ghost-agent",
	})
	if !errors.Is(err, ErrUnknownAgent) {
		t.Errorf("CreateReport(produced_by=ghost-agent) err = %v, want ErrUnknownAgent", err)
	}
}

func TestIntegration_CreateReport_FulfillsAssignment(t *testing.T) {
	reset(t)
	store := NewStore(testPool)
	ctx := t.Context()

	a, err := store.CreateAssignment(ctx, CreateAssignmentParams{
		Topic:      "survey vector index tradeoffs",
		AssignedTo: "research-lab",
		AssignedBy: "hq",
	})
	if err != nil {
		t.Fatalf("CreateAssignment: %v", err)
	}
	if a.Status != StatusOpen || a.FulfilledAt != nil {
		t.Fatalf("new assignment = (status=%q, fulfilled_at=%v), want (open, nil)", a.Status, a.FulfilledAt)
	}

	r, err := store.CreateReport(ctx, CreateReportParams{
		Title:              "vector index survey",
		Body:               "HNSW vs IVFFlat recall/latency",
		ProducedBy:         "research-lab",
		OriginAssignmentID: &a.ID,
	})
	if err != nil {
		t.Fatalf("CreateReport(origin): %v", err)
	}
	if r.OriginAssignmentID == nil || *r.OriginAssignmentID != a.ID {
		t.Errorf("report origin = %v, want %v", r.OriginAssignmentID, a.ID)
	}

	got, err := store.Assignment(ctx, a.ID)
	if err != nil {
		t.Fatalf("Assignment: %v", err)
	}
	if got.Status != StatusFulfilled {
		t.Errorf("assignment status after report = %q, want %q", got.Status, StatusFulfilled)
	}
	if got.FulfilledAt == nil {
		t.Errorf("assignment fulfilled_at = nil, want set")
	}

	// Idempotent: a second report referencing the same (already fulfilled)
	// assignment still creates a report and leaves the assignment fulfilled.
	if _, err := store.CreateReport(ctx, CreateReportParams{
		Title:              "vector index survey addendum",
		ProducedBy:         "research-lab",
		OriginAssignmentID: &a.ID,
	}); err != nil {
		t.Fatalf("second CreateReport(origin): %v", err)
	}
	again, err := store.Assignment(ctx, a.ID)
	if err != nil {
		t.Fatalf("Assignment (after second report): %v", err)
	}
	if again.Status != StatusFulfilled || !again.FulfilledAt.Equal(*got.FulfilledAt) {
		t.Errorf("assignment changed on second report: (status=%q, fulfilled_at=%v), want (fulfilled, %v)",
			again.Status, again.FulfilledAt, got.FulfilledAt)
	}
}

func TestIntegration_OpenAssignments_ShowsUnfulfilled(t *testing.T) {
	reset(t)
	store := NewStore(testPool)
	ctx := t.Context()

	fulfilled, err := store.CreateAssignment(ctx, CreateAssignmentParams{Topic: "topic A", AssignedTo: "research-lab", AssignedBy: "hq"})
	if err != nil {
		t.Fatalf("CreateAssignment A: %v", err)
	}
	unfulfilled, err := store.CreateAssignment(ctx, CreateAssignmentParams{Topic: "topic B", AssignedTo: "research-lab", AssignedBy: "hq"})
	if err != nil {
		t.Fatalf("CreateAssignment B: %v", err)
	}
	if _, err := store.CreateReport(ctx, CreateReportParams{Title: "A findings", ProducedBy: "research-lab", OriginAssignmentID: &fulfilled.ID}); err != nil {
		t.Fatalf("CreateReport: %v", err)
	}

	open, err := store.OpenAssignments(ctx, 10)
	if err != nil {
		t.Fatalf("OpenAssignments: %v", err)
	}
	ids := make(map[uuid.UUID]bool, len(open))
	for i := range open {
		ids[open[i].ID] = true
	}
	if ids[fulfilled.ID] {
		t.Errorf("OpenAssignments includes fulfilled assignment %s; want excluded", fulfilled.ID)
	}
	if !ids[unfulfilled.ID] {
		t.Errorf("OpenAssignments missing unfulfilled assignment %s; an assignment with no report must stay visible", unfulfilled.ID)
	}
}

func TestIntegration_SearchReports(t *testing.T) {
	reset(t)
	store := NewStore(testPool)
	ctx := t.Context()

	hit, err := store.CreateReport(ctx, CreateReportParams{Title: "binary search invariants", Body: "loop boundary correctness", ProducedBy: "research-lab"})
	if err != nil {
		t.Fatalf("CreateReport hit: %v", err)
	}
	if _, err := store.CreateReport(ctx, CreateReportParams{Title: "unrelated cooking notes", Body: "risotto technique", ProducedBy: "research-lab"}); err != nil {
		t.Fatalf("CreateReport miss: %v", err)
	}

	res, err := store.Search(ctx, "binary search", 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("Search(%q) returned %d results, want 1", "binary search", len(res))
	}
	if res[0].ID != hit.ID {
		t.Errorf("Search top hit = %q, want %q", res[0].Title, hit.Title)
	}
	if res[0].TrustStatus != TrustLow {
		t.Errorf("search hit trust = %q, want %q (searchable from creation at low_trust)", res[0].TrustStatus, TrustLow)
	}
}

func TestIntegration_SetTrust(t *testing.T) {
	reset(t)
	store := NewStore(testPool)
	ctx := t.Context()

	r, err := store.CreateReport(ctx, CreateReportParams{Title: "promote me", ProducedBy: "research-lab"})
	if err != nil {
		t.Fatalf("CreateReport: %v", err)
	}

	up, err := store.SetTrust(ctx, r.ID, TrustTrusted)
	if err != nil {
		t.Fatalf("SetTrust(trusted): %v", err)
	}
	if up.TrustStatus != TrustTrusted {
		t.Errorf("after SetTrust, trust = %q, want %q", up.TrustStatus, TrustTrusted)
	}

	if _, err := store.SetTrust(ctx, r.ID, "bogus"); !errors.Is(err, ErrInvalidTrust) {
		t.Errorf("SetTrust(bogus) err = %v, want ErrInvalidTrust", err)
	}
	if _, err := store.SetTrust(ctx, uuid.New(), TrustTrusted); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetTrust(missing id) err = %v, want ErrNotFound", err)
	}
}
