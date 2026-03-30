package exec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/ai"
	"github.com/Koopa0/koopa0.dev/internal/budget"
)

// semaphoreTimeout is the hard deadline for acquiring a worker slot.
// If a flow hangs and never releases its semaphore, the dispatch loop
// will abandon the job after this duration rather than blocking shutdown.
const semaphoreTimeout = 30 * time.Second

// defaultFlowTimeout is the hard deadline for a single flow execution.
// Set to 3 minutes: safely above the longest observed flow (weekly-review ~120s)
// while preventing a hung AI API from holding a semaphore slot forever.
const defaultFlowTimeout = 3 * time.Minute

// Runner manages a pool of workers that execute AI flows.
// Jobs are persisted to the flow_runs table before being dispatched
// to the channel, ensuring recoverability via cron retry.
type Runner struct {
	store    *Store
	registry *ai.Registry
	alerter  Alerter
	observer *MetricsObserver // optional: records execution metrics
	jobs     chan uuid.UUID
	sem      chan struct{} // concurrency semaphore
	logger   *slog.Logger
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// SetObserver sets the optional flow execution metrics observer.
func (r *Runner) SetObserver(o *MetricsObserver) { r.observer = o }

// New returns a Runner with the given concurrency limit.
// Channel buffer is set to workers * 2 to avoid blocking callers
// while still bounding in-memory queue size.
func New(store *Store, registry *ai.Registry, workers int, alerter Alerter, logger *slog.Logger) *Runner {
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
		if updateErr := r.store.UpdateFailed(ctx, runID, errMsg); updateErr != nil {
			logger.Error("marking flow run failed", "error", updateErr)
		}
		// Unknown flow is a permanent failure — always alert regardless of attempt count.
		r.alertAlways(ctx, run, errMsg)
		return
	}

	logger = logger.With("flow", run.FlowName)

	if updateErr := r.store.UpdateRunning(ctx, runID); updateErr != nil {
		logger.Error("marking flow run running", "error", updateErr)
		return
	}

	// Apply per-job timeout so a hung AI API cannot hold a semaphore slot forever.
	execCtx, execCancel := context.WithTimeout(ctx, defaultFlowTimeout)
	defer execCancel()

	start := time.Now()
	output, err := f.Run(execCtx, run.Input)
	elapsed := time.Since(start)

	if err != nil {
		logger.Error("flow execution failed", "error", err, "duration", elapsed)
		r.observeFlow(run.FlowName, "failed", elapsed)
		if uerr := r.store.UpdateFailed(ctx, runID, err.Error()); uerr != nil {
			logger.Error("marking flow run failed", "error", uerr)
		}
		// Content blocked by safety filter is permanent — alert immediately, no retry.
		if errors.Is(err, ai.ErrContentBlocked) {
			r.alertAlways(ctx, run, err.Error())
			return
		}
		// Budget exhaustion is permanent until the daily reset — retrying wastes
		// all attempts with the same error. Alert immediately.
		if errors.Is(err, budget.ErrOverBudget) {
			r.alertAlways(ctx, run, err.Error())
			return
		}
		// attempt was incremented by UpdateRunning, so current attempt = run.Attempt + 1
		r.alertIfFinal(ctx, run, err.Error())
		return
	}

	r.observeFlow(run.FlowName, "completed", elapsed)

	if err := r.store.UpdateCompleted(ctx, runID, output); err != nil {
		logger.Error("marking flow run completed", "error", err)
		return
	}

	logger.Info("flow run completed", "duration", elapsed)
}

// observeFlow records flow execution duration if an observer is configured.
func (r *Runner) observeFlow(flowName, status string, d time.Duration) {
	if r.observer != nil {
		r.observer.ObserveFlowDuration(flowName, status, d)
	}
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
	if err := r.alerter.Alert(ctx, &alertRun); err != nil {
		r.logger.Error("sending failure alert", "run_id", run.ID, "error", err)
	}
}
