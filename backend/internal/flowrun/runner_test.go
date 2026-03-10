//go:build !integration

package flowrun

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/flow"
)

// --- mock store ---

// mockStore is an in-memory runnerStore for unit testing.
// All mutations are protected by mu so tests can call Stop() and then
// read state without a data race.
type mockStore struct {
	mu   sync.Mutex
	runs map[uuid.UUID]*Run
}

func newMockStore() *mockStore {
	return &mockStore{runs: make(map[uuid.UUID]*Run)}
}

func (m *mockStore) CreateRun(_ context.Context, flowName string, input json.RawMessage) (*Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := &Run{
		ID:       uuid.New(),
		FlowName: flowName,
		Input:    input,
		Status:   StatusPending,
	}
	m.runs[r.ID] = r
	return r, nil
}

func (m *mockStore) Run(_ context.Context, id uuid.UUID) (*Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return nil, ErrNotFound
	}
	// Return a copy to avoid caller mutations racing with store mutations.
	cp := *r
	return &cp, nil
}

func (m *mockStore) UpdateRunning(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return ErrNotFound
	}
	r.Status = StatusRunning
	return nil
}

func (m *mockStore) UpdateCompleted(_ context.Context, id uuid.UUID, output json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return ErrNotFound
	}
	r.Status = StatusCompleted
	r.Output = output
	return nil
}

func (m *mockStore) UpdateFailed(_ context.Context, id uuid.UUID, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return ErrNotFound
	}
	r.Status = StatusFailed
	r.Error = &errMsg
	return nil
}

// status returns the current status of a run. Safe for concurrent use.
func (m *mockStore) status(id uuid.UUID) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runs[id].Status
}

// --- mock flow ---

// mockFlow is a controllable flow.Flow implementation.
// runFn is called by Run; set it per test-case to drive happy/error paths.
type mockFlow struct {
	name  string
	runFn func(ctx context.Context, input json.RawMessage) (json.RawMessage, error)
}

func (f *mockFlow) Name() string { return f.name }

func (f *mockFlow) Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	return f.runFn(ctx, input)
}

// --- helpers ---

// newTestRunner builds a Runner wired to mock dependencies.
// workers=1 keeps tests deterministic; buffer=4 avoids channel-full in most cases.
func newTestRunner(t *testing.T, store runnerStore, registry *flow.Registry) *Runner {
	t.Helper()
	logger := slog.Default()
	r := &Runner{
		store:    store,
		registry: registry,
		jobs:     make(chan uuid.UUID, 4),
		sem:      make(chan struct{}, 1),
		logger:   logger,
	}
	return r
}

// waitForStatus polls until the run reaches want or the deadline passes.
// Using polling here instead of time.Sleep because we cannot instrument the
// store with a condition variable without changing production code.
// The poll interval is 1 ms, making it effectively instantaneous in practice.
func waitForStatus(t *testing.T, store *mockStore, id uuid.UUID, want Status) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if store.status(id) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for run %s to reach status %q (current: %q)", id, want, store.status(id))
}

// --- tests ---

func TestRunner_HappyPath(t *testing.T) {
	t.Parallel()

	successOutput := json.RawMessage(`{"ok":true}`)

	tests := []struct {
		name       string
		flowName   string
		input      json.RawMessage
		wantStatus Status
		wantOutput json.RawMessage
	}{
		{
			name:       "flow completes successfully",
			flowName:   "test-flow",
			input:      json.RawMessage(`{"x":1}`),
			wantStatus: StatusCompleted,
			wantOutput: successOutput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newMockStore()
			mf := &mockFlow{
				name: tt.flowName,
				runFn: func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
					return successOutput, nil
				},
			}
			registry := flow.NewRegistry(mf)
			runner := newTestRunner(t, store, registry)

			ctx := t.Context()
			runner.Start(ctx)
			t.Cleanup(runner.Stop)

			err := runner.Submit(ctx, tt.flowName, tt.input)
			if err != nil {
				t.Fatalf("Submit: unexpected error: %v", err)
			}

			// Find the run that was created (there will be exactly one).
			var runID uuid.UUID
			store.mu.Lock()
			for id := range store.runs {
				runID = id
			}
			store.mu.Unlock()

			waitForStatus(t, store, runID, tt.wantStatus)

			store.mu.Lock()
			got := store.runs[runID]
			store.mu.Unlock()

			if got.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", got.Status, tt.wantStatus)
			}
			if diff := cmp.Diff(string(tt.wantOutput), string(got.Output)); diff != "" {
				t.Errorf("output mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRunner_ErrorPath(t *testing.T) {
	t.Parallel()

	flowErr := errors.New("ai exploded")

	tests := []struct {
		name          string
		runFn         func(context.Context, json.RawMessage) (json.RawMessage, error)
		wantStatus    Status
		wantErrSubstr string
	}{
		{
			name: "flow.Run returns error → run marked failed",
			runFn: func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
				return nil, flowErr
			},
			wantStatus:    StatusFailed,
			wantErrSubstr: "ai exploded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newMockStore()
			mf := &mockFlow{name: "err-flow", runFn: tt.runFn}
			registry := flow.NewRegistry(mf)
			runner := newTestRunner(t, store, registry)

			ctx := t.Context()
			runner.Start(ctx)
			t.Cleanup(runner.Stop)

			if err := runner.Submit(ctx, "err-flow", json.RawMessage(`{}`)); err != nil {
				t.Fatalf("Submit: %v", err)
			}

			var runID uuid.UUID
			store.mu.Lock()
			for id := range store.runs {
				runID = id
			}
			store.mu.Unlock()

			waitForStatus(t, store, runID, tt.wantStatus)

			store.mu.Lock()
			got := store.runs[runID]
			store.mu.Unlock()

			if got.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", got.Status, tt.wantStatus)
			}
			if got.Error == nil {
				t.Fatal("expected non-nil error message on run, got nil")
			}
			if *got.Error != tt.wantErrSubstr {
				t.Errorf("error message = %q, want %q", *got.Error, tt.wantErrSubstr)
			}
		})
	}
}

func TestRunner_UnknownFlow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		flowName string
	}{
		{
			name:     "unregistered flow name → run marked failed immediately",
			flowName: "does-not-exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newMockStore()
			// Empty registry — no flows registered.
			registry := flow.NewRegistry()
			runner := newTestRunner(t, store, registry)

			ctx := t.Context()
			runner.Start(ctx)
			t.Cleanup(runner.Stop)

			if err := runner.Submit(ctx, tt.flowName, json.RawMessage(`{}`)); err != nil {
				t.Fatalf("Submit: %v", err)
			}

			var runID uuid.UUID
			store.mu.Lock()
			for id := range store.runs {
				runID = id
			}
			store.mu.Unlock()

			waitForStatus(t, store, runID, StatusFailed)

			store.mu.Lock()
			got := store.runs[runID]
			store.mu.Unlock()

			if got.Status != StatusFailed {
				t.Errorf("status = %q, want %q", got.Status, StatusFailed)
			}
			if got.Error == nil {
				t.Fatal("expected non-nil error on run for unknown flow")
			}
		})
	}
}

func TestRunner_GracefulShutdown(t *testing.T) {
	t.Parallel()

	// started signals that the flow goroutine is executing.
	started := make(chan struct{})
	// unblock allows the flow to finish after we have confirmed it started.
	unblock := make(chan struct{})

	store := newMockStore()
	mf := &mockFlow{
		name: "slow-flow",
		runFn: func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
			close(started)
			<-unblock
			return json.RawMessage(`{"done":true}`), nil
		},
	}
	registry := flow.NewRegistry(mf)
	runner := newTestRunner(t, store, registry)

	ctx := t.Context()
	runner.Start(ctx)

	if err := runner.Submit(ctx, "slow-flow", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	// Wait until the flow has started executing before stopping.
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("flow did not start within deadline")
	}

	// Stop() in a separate goroutine; verify it blocks until we unblock the flow.
	stopped := make(chan struct{})
	go func() {
		runner.Stop()
		close(stopped)
	}()

	// Stop() must not return before the in-flight job finishes.
	select {
	case <-stopped:
		t.Fatal("Stop() returned before in-flight job completed")
	case <-time.After(50 * time.Millisecond):
		// Expected: Stop() is still waiting.
	}

	// Allow the flow to finish, then Stop() should return.
	close(unblock)

	select {
	case <-stopped:
		// Correct: Stop() returned after job finished.
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return after job completed")
	}

	// Confirm the run reached completed status.
	var runID uuid.UUID
	store.mu.Lock()
	for id := range store.runs {
		runID = id
	}
	store.mu.Unlock()

	if got := store.status(runID); got != StatusCompleted {
		t.Errorf("run status after graceful shutdown = %q, want %q", got, StatusCompleted)
	}
}

func TestRunner_ChannelFull(t *testing.T) {
	t.Parallel()

	// Build a runner with a tiny buffer (1) and NO running dispatch loop so
	// the channel stays full after the first submit.
	store := newMockStore()
	registry := flow.NewRegistry()
	runner := &Runner{
		store:    store,
		registry: registry,
		jobs:     make(chan uuid.UUID, 1), // capacity 1
		sem:      make(chan struct{}, 1),
		logger:   slog.Default(),
	}
	// Do NOT call Start — dispatch loop is not running.

	ctx := t.Context()

	// First submit fills the channel.
	if err := runner.Submit(ctx, "flow-a", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("first Submit: %v", err)
	}

	// Second submit hits the full channel (non-blocking select falls through).
	if err := runner.Submit(ctx, "flow-b", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("second Submit: %v", err)
	}

	// Both runs must be persisted in the store regardless of channel state.
	store.mu.Lock()
	count := len(store.runs)
	store.mu.Unlock()

	if count != 2 {
		t.Errorf("expected 2 persisted runs after channel-full submit, got %d", count)
	}

	// All persisted runs should still be pending (no worker executed them).
	store.mu.Lock()
	for id, r := range store.runs {
		if r.Status != StatusPending {
			t.Errorf("run %s: status = %q, want %q", id, r.Status, StatusPending)
		}
	}
	store.mu.Unlock()
}

// TestRunner_MockFlowOutputUnmarshal verifies that the output produced by a
// mock flow can be cleanly unmarshalled back into flow.ContentReviewOutput.
func TestRunner_MockFlowOutputUnmarshal(t *testing.T) {
	t.Parallel()

	mockContentReview := flow.NewMockContentReview()
	output, err := mockContentReview.Run(t.Context(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("mock flow Run: %v", err)
	}

	var got flow.ContentReviewOutput
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatalf("unmarshal ContentReviewOutput: %v", err)
	}

	want := flow.ContentReviewOutput{
		Proofread: &flow.ReviewResult{
			Level:       "auto",
			Notes:       "mock mode",
			Corrections: []string{},
		},
		Excerpt:     "Mock excerpt for testing.",
		Tags:        []string{},
		ReadingTime: 1,
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ContentReviewOutput mismatch (-want +got):\n%s", diff)
	}
}
