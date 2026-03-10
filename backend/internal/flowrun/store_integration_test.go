//go:build integration

package flowrun

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx, "postgres:17",
		postgres.WithDatabase("flowrun_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		log.Fatalf("starting postgres container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("getting connection string: %v", err)
	}

	testPool, err = pgxpool.New(ctx, connStr)
	if err != nil {
		log.Fatalf("creating pool: %v", err)
	}

	// Apply schema
	if err := applySchema(ctx, testPool); err != nil {
		log.Fatalf("applying schema: %v", err)
	}

	code := m.Run()

	testPool.Close()
	if err := pgContainer.Terminate(ctx); err != nil {
		log.Printf("terminating container: %v", err)
	}
	os.Exit(code)
}

func applySchema(ctx context.Context, pool *pgxpool.Pool) error {
	// Only create the enums and tables needed for flow_runs.
	schema := `
		CREATE TYPE flow_status AS ENUM ('pending', 'running', 'completed', 'failed');
		CREATE TABLE flow_runs (
			id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			flow_name    TEXT NOT NULL,
			input        JSONB NOT NULL,
			output       JSONB,
			status       flow_status NOT NULL DEFAULT 'pending',
			error        TEXT,
			attempt      INT NOT NULL DEFAULT 0,
			max_attempts INT NOT NULL DEFAULT 3,
			started_at   TIMESTAMPTZ,
			ended_at     TIMESTAMPTZ,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX idx_flow_runs_status ON flow_runs (status);
		CREATE INDEX idx_flow_runs_retry ON flow_runs (created_at) WHERE status = 'failed';
		CREATE INDEX idx_flow_runs_created_at ON flow_runs (created_at DESC);
	`
	_, err := pool.Exec(ctx, schema)
	return err
}

// truncateFlowRuns removes all rows between tests.
func truncateFlowRuns(t *testing.T) {
	t.Helper()
	_, err := testPool.Exec(t.Context(), "TRUNCATE flow_runs")
	if err != nil {
		t.Fatalf("truncating flow_runs: %v", err)
	}
}

// setCreatedAt backdates a flow run's created_at for stuck-pending tests.
func setCreatedAt(t *testing.T, id uuid.UUID, d time.Duration) {
	t.Helper()
	_, err := testPool.Exec(t.Context(),
		"UPDATE flow_runs SET created_at = now() - $1::interval WHERE id = $2",
		d.String(), id)
	if err != nil {
		t.Fatalf("setting created_at for %s: %v", id, err)
	}
}

// setStartedAt backdates a flow run's started_at for stuck-running tests.
func setStartedAt(t *testing.T, id uuid.UUID, d time.Duration) {
	t.Helper()
	_, err := testPool.Exec(t.Context(),
		"UPDATE flow_runs SET started_at = now() - $1::interval WHERE id = $2",
		d.String(), id)
	if err != nil {
		t.Fatalf("setting started_at for %s: %v", id, err)
	}
}

// setAttempt directly sets the attempt count for a flow run.
func setAttempt(t *testing.T, id uuid.UUID, attempt int) {
	t.Helper()
	_, err := testPool.Exec(t.Context(),
		"UPDATE flow_runs SET attempt = $1 WHERE id = $2",
		attempt, id)
	if err != nil {
		t.Fatalf("setting attempt for %s: %v", id, err)
	}
}

func newStore() *Store {
	return NewStore(testPool)
}

func TestStore_Lifecycle(t *testing.T) {
	truncateFlowRuns(t)
	s := newStore()
	ctx := t.Context()
	input := json.RawMessage(`{"content_id":"abc"}`)

	// Create
	run, err := s.CreateRun(ctx, "test-flow", input)
	if err != nil {
		t.Fatalf("CreateRun() error: %v", err)
	}
	if run.Status != StatusPending {
		t.Fatalf("CreateRun() status = %q, want %q", run.Status, StatusPending)
	}
	if run.Attempt != 0 {
		t.Fatalf("CreateRun() attempt = %d, want 0", run.Attempt)
	}

	// Read back
	got, err := s.Run(ctx, run.ID)
	if err != nil {
		t.Fatalf("Run(%s) error: %v", run.ID, err)
	}
	if diff := cmp.Diff(run, got, cmpopts.EquateApproxTime(time.Second)); diff != "" {
		t.Errorf("Run(%s) mismatch (-want +got):\n%s", run.ID, diff)
	}

	// UpdateRunning
	if err := s.UpdateRunning(ctx, run.ID); err != nil {
		t.Fatalf("UpdateRunning(%s) error: %v", run.ID, err)
	}
	got, _ = s.Run(ctx, run.ID)
	if got.Status != StatusRunning {
		t.Errorf("after UpdateRunning: status = %q, want %q", got.Status, StatusRunning)
	}
	if got.Attempt != 1 {
		t.Errorf("after UpdateRunning: attempt = %d, want 1", got.Attempt)
	}
	if got.StartedAt == nil {
		t.Error("after UpdateRunning: started_at is nil")
	}

	// UpdateCompleted
	output := json.RawMessage(`{"result":"ok"}`)
	if err := s.UpdateCompleted(ctx, run.ID, output); err != nil {
		t.Fatalf("UpdateCompleted(%s) error: %v", run.ID, err)
	}
	got, _ = s.Run(ctx, run.ID)
	if got.Status != StatusCompleted {
		t.Errorf("after UpdateCompleted: status = %q, want %q", got.Status, StatusCompleted)
	}
	if got.EndedAt == nil {
		t.Error("after UpdateCompleted: ended_at is nil")
	}
	// Compare unmarshalled JSON — PostgreSQL JSONB normalizes whitespace.
	var wantOut, gotOut any
	if err := json.Unmarshal(output, &wantOut); err != nil {
		t.Fatalf("unmarshalling want output: %v", err)
	}
	if err := json.Unmarshal(got.Output, &gotOut); err != nil {
		t.Fatalf("unmarshalling got output: %v", err)
	}
	if diff := cmp.Diff(wantOut, gotOut); diff != "" {
		t.Errorf("after UpdateCompleted: output mismatch (-want +got):\n%s", diff)
	}
}

func TestStore_Lifecycle_Failed(t *testing.T) {
	truncateFlowRuns(t)
	s := newStore()
	ctx := t.Context()

	run, err := s.CreateRun(ctx, "fail-flow", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("CreateRun() error: %v", err)
	}

	if err := s.UpdateRunning(ctx, run.ID); err != nil {
		t.Fatalf("UpdateRunning() error: %v", err)
	}

	if err := s.UpdateFailed(ctx, run.ID, "something broke"); err != nil {
		t.Fatalf("UpdateFailed() error: %v", err)
	}

	got, _ := s.Run(ctx, run.ID)
	if got.Status != StatusFailed {
		t.Errorf("after UpdateFailed: status = %q, want %q", got.Status, StatusFailed)
	}
	if got.Error == nil || *got.Error != "something broke" {
		t.Errorf("after UpdateFailed: error = %v, want %q", got.Error, "something broke")
	}
	if got.EndedAt == nil {
		t.Error("after UpdateFailed: ended_at is nil")
	}
}

func TestStore_Run_NotFound(t *testing.T) {
	truncateFlowRuns(t)
	s := newStore()

	_, err := s.Run(t.Context(), uuid.New())
	if err != ErrNotFound {
		t.Fatalf("Run(missing) error = %v, want ErrNotFound", err)
	}
}

func TestStore_Runs_Pagination(t *testing.T) {
	truncateFlowRuns(t)
	s := newStore()
	ctx := t.Context()

	// Create 5 runs
	for range 5 {
		if _, err := s.CreateRun(ctx, "test", json.RawMessage(`{}`)); err != nil {
			t.Fatalf("CreateRun() error: %v", err)
		}
	}

	runs, total, err := s.Runs(ctx, Filter{Page: 1, PerPage: 2})
	if err != nil {
		t.Fatalf("Runs() error: %v", err)
	}
	if total != 5 {
		t.Errorf("Runs() total = %d, want 5", total)
	}
	if len(runs) != 2 {
		t.Errorf("Runs() len = %d, want 2", len(runs))
	}

	// Filter by status
	if _, err := s.CreateRun(ctx, "test", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("CreateRun() error: %v", err)
	}
	// Mark one as failed
	runs2, _, _ := s.Runs(ctx, Filter{Page: 1, PerPage: 100})
	if err := s.UpdateRunning(ctx, runs2[0].ID); err != nil {
		t.Fatalf("UpdateRunning() error: %v", err)
	}
	if err := s.UpdateFailed(ctx, runs2[0].ID, "err"); err != nil {
		t.Fatalf("UpdateFailed() error: %v", err)
	}

	failedStatus := StatusFailed
	failedRuns, failedTotal, err := s.Runs(ctx, Filter{Page: 1, PerPage: 100, Status: &failedStatus})
	if err != nil {
		t.Fatalf("Runs(status=failed) error: %v", err)
	}
	if failedTotal != 1 {
		t.Errorf("Runs(status=failed) total = %d, want 1", failedTotal)
	}
	if len(failedRuns) != 1 {
		t.Errorf("Runs(status=failed) len = %d, want 1", len(failedRuns))
	}
}

func TestStore_RetryableFlowRuns(t *testing.T) {
	s := newStore()
	ctx := t.Context()

	tests := []struct {
		name       string
		setup      func(t *testing.T) uuid.UUID
		wantPicked bool
	}{
		{
			name: "failed with attempt < max → picked up",
			setup: func(t *testing.T) uuid.UUID {
				t.Helper()
				run, _ := s.CreateRun(ctx, "f", json.RawMessage(`{}`))
				_ = s.UpdateRunning(ctx, run.ID)
				_ = s.UpdateFailed(ctx, run.ID, "err")
				// attempt=1 after UpdateRunning, max_attempts=3
				return run.ID
			},
			wantPicked: true,
		},
		{
			name: "failed with attempt >= max → NOT picked up",
			setup: func(t *testing.T) uuid.UUID {
				t.Helper()
				run, _ := s.CreateRun(ctx, "f", json.RawMessage(`{}`))
				_ = s.UpdateRunning(ctx, run.ID)
				_ = s.UpdateFailed(ctx, run.ID, "err")
				setAttempt(t, run.ID, 3) // at max
				return run.ID
			},
			wantPicked: false,
		},
		{
			name: "stuck pending (created_at > 5min ago) → picked up",
			setup: func(t *testing.T) uuid.UUID {
				t.Helper()
				run, _ := s.CreateRun(ctx, "f", json.RawMessage(`{}`))
				setCreatedAt(t, run.ID, 6*time.Minute)
				return run.ID
			},
			wantPicked: true,
		},
		{
			name: "fresh pending (created_at < 5min ago) → NOT picked up",
			setup: func(t *testing.T) uuid.UUID {
				t.Helper()
				run, _ := s.CreateRun(ctx, "f", json.RawMessage(`{}`))
				// created_at is now(), well within 5 min
				return run.ID
			},
			wantPicked: false,
		},
		{
			name: "stuck running (started_at > 10min ago) → picked up",
			setup: func(t *testing.T) uuid.UUID {
				t.Helper()
				run, _ := s.CreateRun(ctx, "f", json.RawMessage(`{}`))
				_ = s.UpdateRunning(ctx, run.ID) // attempt=1
				setStartedAt(t, run.ID, 11*time.Minute)
				return run.ID
			},
			wantPicked: true,
		},
		{
			name: "recently running (started_at < 10min ago) → NOT picked up",
			setup: func(t *testing.T) uuid.UUID {
				t.Helper()
				run, _ := s.CreateRun(ctx, "f", json.RawMessage(`{}`))
				_ = s.UpdateRunning(ctx, run.ID)
				// started_at is now(), well within 10 min
				return run.ID
			},
			wantPicked: false,
		},
		{
			name: "completed → NOT picked up",
			setup: func(t *testing.T) uuid.UUID {
				t.Helper()
				run, _ := s.CreateRun(ctx, "f", json.RawMessage(`{}`))
				_ = s.UpdateRunning(ctx, run.ID)
				_ = s.UpdateCompleted(ctx, run.ID, json.RawMessage(`{}`))
				return run.ID
			},
			wantPicked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			truncateFlowRuns(t)
			id := tt.setup(t)

			runs, err := s.RetryableRuns(ctx)
			if err != nil {
				t.Fatalf("RetryableRuns() error: %v", err)
			}

			picked := false
			for _, r := range runs {
				if r.ID == id {
					picked = true
					if r.Status != StatusPending {
						t.Errorf("RetryableRuns() returned run with status %q, want %q", r.Status, StatusPending)
					}
					break
				}
			}

			if picked != tt.wantPicked {
				t.Errorf("RetryableRuns() picked = %v, want %v", picked, tt.wantPicked)
			}
		})
	}
}

func TestStore_RetryableFlowRuns_ConcurrentNoDuplicatePickup(t *testing.T) {
	truncateFlowRuns(t)
	s := newStore()
	ctx := t.Context()

	// Create 10 failed runs, all retryable.
	var ids []uuid.UUID
	for range 10 {
		run, err := s.CreateRun(ctx, "f", json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("CreateRun() error: %v", err)
		}
		if err := s.UpdateRunning(ctx, run.ID); err != nil {
			t.Fatalf("UpdateRunning() error: %v", err)
		}
		if err := s.UpdateFailed(ctx, run.ID, "err"); err != nil {
			t.Fatalf("UpdateFailed() error: %v", err)
		}
		ids = append(ids, run.ID)
	}

	// Two goroutines call RetryableRuns concurrently.
	// Thanks to UPDATE...RETURNING with row-level locking,
	// the ID sets returned by each call must be disjoint.
	var (
		mu    sync.Mutex
		runs1 []Run
		runs2 []Run
		err1  error
		err2  error
		wg    sync.WaitGroup
		ready = make(chan struct{})
	)

	wg.Go(func() {
		<-ready
		runs1, err1 = s.RetryableRuns(ctx)
	})
	wg.Go(func() {
		<-ready
		runs2, err2 = s.RetryableRuns(ctx)
	})

	close(ready) // start both goroutines simultaneously
	wg.Wait()

	if err1 != nil {
		t.Fatalf("goroutine 1: RetryableRuns() error: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("goroutine 2: RetryableRuns() error: %v", err2)
	}

	// Build ID sets and check for intersection.
	mu.Lock()
	defer mu.Unlock()

	set1 := make(map[uuid.UUID]bool, len(runs1))
	for _, r := range runs1 {
		set1[r.ID] = true
	}

	for _, r := range runs2 {
		if set1[r.ID] {
			t.Errorf("duplicate pickup: run %s returned by both goroutines", r.ID)
		}
	}

	// All 10 runs should be picked up across both calls.
	total := len(runs1) + len(runs2)
	if total != 10 {
		t.Errorf("total picked = %d, want 10 (goroutine1=%d, goroutine2=%d)", total, len(runs1), len(runs2))
	}
}
