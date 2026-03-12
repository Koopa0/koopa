package flowrun

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/flow"
)

// semaphoreTimeout is the hard deadline for acquiring a worker slot.
// If a flow hangs and never releases its semaphore, the dispatch loop
// will abandon the job after this duration rather than blocking shutdown.
const semaphoreTimeout = 30 * time.Second

// runnerStore is the minimal store interface the Runner needs.
// Defined here (consumer side) so unit tests can substitute a mock.
type runnerStore interface {
	CreateRun(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) (*Run, error)
	Run(ctx context.Context, id uuid.UUID) (*Run, error)
	PendingRunExists(ctx context.Context, flowName string, contentID *uuid.UUID) (bool, error)
	UpdateRunning(ctx context.Context, id uuid.UUID) error
	UpdateCompleted(ctx context.Context, id uuid.UUID, output json.RawMessage) error
	UpdateFailed(ctx context.Context, id uuid.UUID, errMsg string) error
}

// Runner manages a pool of workers that execute AI flows.
// Jobs are persisted to the flow_runs table before being dispatched
// to the channel, ensuring recoverability via cron retry.
type Runner struct {
	store    runnerStore
	registry *flow.Registry
	alerter  Alerter
	jobs     chan uuid.UUID
	sem      chan struct{} // concurrency semaphore
	logger   *slog.Logger
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// New returns a Runner with the given concurrency limit.
// Channel buffer is set to workers * 2 to avoid blocking callers
// while still bounding in-memory queue size.
func New(store *Store, registry *flow.Registry, workers int, alerter Alerter, logger *slog.Logger) *Runner {
	return &Runner{
		store:    store,
		registry: registry,
		alerter:  alerter,
		jobs:     make(chan uuid.UUID, workers*2),
		sem:      make(chan struct{}, workers),
		logger:   logger,
	}
}

// Start launches the worker dispatch loop. Call Stop to drain.
func (r *Runner) Start(ctx context.Context) {
	ctx, r.cancel = context.WithCancel(ctx)

	r.wg.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case runID := <-r.jobs:
				// Acquire semaphore with ctx + hard timeout to prevent
				// shutdown deadlock if a flow hangs and never releases.
				t := time.NewTimer(semaphoreTimeout)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case r.sem <- struct{}{}:
					t.Stop()
				case <-t.C:
					r.logger.Warn("semaphore acquire timed out, skipping job", "run_id", runID)
					continue
				}
				r.wg.Go(func() {
					defer func() { <-r.sem }() // release semaphore
					r.execute(ctx, runID)
				})
			}
		}
	})
}

// Stop signals the dispatch loop to stop and waits for all workers to drain.
func (r *Runner) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
}

// Submit creates a flow_runs row and dispatches it to the worker pool.
// If contentID is non-nil, dedup check prevents duplicate submissions
// for the same flow+content combination that is already pending or running.
// If the channel is full, the job is still persisted and will be picked up
// by the cron retry scanner.
func (r *Runner) Submit(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) error {
	// default nil input to empty JSON object to satisfy NOT NULL constraint
	if input == nil {
		input = json.RawMessage("{}")
	}

	// dedup: skip if a pending/running run already exists for this content
	if contentID != nil {
		exists, err := r.store.PendingRunExists(ctx, flowName, contentID)
		if err != nil {
			return err
		}
		if exists {
			r.logger.Info("skipped duplicate submit", "flow_name", flowName, "content_id", contentID)
			return nil
		}
	}

	run, err := r.store.CreateRun(ctx, flowName, input, contentID)
	if err != nil {
		return fmt.Errorf("submitting flow %s: %w", flowName, err)
	}

	r.logger.Info("flow run submitted", "id", run.ID, "flow", flowName)

	// Non-blocking send: if channel is full, cron will pick it up.
	select {
	case r.jobs <- run.ID:
	default:
		r.logger.Warn("flow run channel full, relying on cron retry", "id", run.ID, "flow", flowName)
	}

	return nil
}

// Requeue sends an existing flow run ID to the worker channel for re-execution.
// Used by the cron retry scanner for runs already persisted in the flow_runs table.
func (r *Runner) Requeue(runID uuid.UUID) {
	select {
	case r.jobs <- runID:
	default:
		r.logger.Warn("flow run channel full during requeue", "id", runID)
	}
}

// execute runs a single flow and updates the flow_runs table accordingly.
func (r *Runner) execute(ctx context.Context, runID uuid.UUID) {
	logger := r.logger.With("run_id", runID)

	run, err := r.store.Run(ctx, runID)
	if err != nil {
		logger.Error("reading flow run", "error", err)
		return
	}

	f := r.registry.Flow(run.FlowName)
	if f == nil {
		errMsg := "unknown flow: " + run.FlowName
		logger.Error(errMsg)
		if err := r.store.UpdateFailed(ctx, runID, errMsg); err != nil {
			logger.Error("marking flow run failed", "error", err)
		}
		// Unknown flow is a permanent failure — always alert regardless of attempt count.
		r.alertAlways(ctx, run, errMsg)
		return
	}

	logger = logger.With("flow", run.FlowName)

	if err := r.store.UpdateRunning(ctx, runID); err != nil {
		logger.Error("marking flow run running", "error", err)
		return
	}

	output, err := f.Run(ctx, run.Input)
	if err != nil {
		logger.Error("flow execution failed", "error", err)
		if uerr := r.store.UpdateFailed(ctx, runID, err.Error()); uerr != nil {
			logger.Error("marking flow run failed", "error", uerr)
		}
		// attempt was incremented by UpdateRunning, so current attempt = run.Attempt + 1
		r.alertIfFinal(ctx, run, err.Error())
		return
	}

	if err := r.store.UpdateCompleted(ctx, runID, output); err != nil {
		logger.Error("marking flow run completed", "error", err)
		return
	}

	logger.Info("flow run completed")
}

// alertIfFinal sends an alert if this was the last attempt.
// Called after UpdateRunning has incremented the attempt counter.
func (r *Runner) alertIfFinal(ctx context.Context, run *Run, errMsg string) {
	// attempt was incremented by UpdateRunning; next attempt = run.Attempt + 1
	if run.Attempt+1 >= run.MaxAttempts {
		r.alertAlways(ctx, run, errMsg)
	}
}

// alertAlways unconditionally sends a failure alert.
// Used for permanent failures (e.g. unknown flow) where retry won't help.
func (r *Runner) alertAlways(ctx context.Context, run *Run, errMsg string) {
	alertRun := *run
	alertRun.Error = &errMsg
	if err := r.alerter.Alert(ctx, alertRun); err != nil {
		r.logger.Error("sending failure alert", "run_id", run.ID, "error", err)
	}
}
