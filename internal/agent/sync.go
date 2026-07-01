// Copyright 2026 Koopa. All rights reserved.

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// SyncResult summarizes the outcome of a SyncToTable run. Returned for
// observability (startup log, metrics) but not otherwise actionable — sync
// failures surface as errors from SyncToTable itself.
type SyncResult struct {
	// Active is the count of rows upserted as active after this run.
	Active int
	// Retired is the count of rows that transitioned to retired (i.e. were
	// present in the DB but absent from BuiltinAgents).
	Retired int
	// AlreadyRetired is the count of rows that were already in the retired
	// state and remained so. Informational only.
	AlreadyRetired int
}

// SyncToTable reconciles the agents table against the Go registry. It is
// intended to run once at application startup, before HTTP serving begins:
//
//  1. Every entry in the registry is upserted as active.
//  2. Every DB row whose name is not in the registry is transitioned to
//     retired (if not already).
//  3. The registry's in-memory Status field is updated for any entry that
//     the DB reports as retired, so registry lookups pick up retirement
//     without requiring a live DB lookup on every call.
//
// The function takes a context with a short timeout so a slow or unresponsive
// DB does not hang startup indefinitely — the caller is expected to provide
// one.
func SyncToTable(ctx context.Context, r *Registry, store *Store, mp metric.MeterProvider, logger *slog.Logger) (SyncResult, error) {
	if r == nil || store == nil {
		return SyncResult{}, fmt.Errorf("agent sync: registry and store must be non-nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	startedAt := time.Now()
	result, err := syncCore(ctx, r, store, logger)
	recordSyncMetrics(ctx, mp, startedAt, err, logger)
	if err != nil {
		return result, err
	}

	logger.Info("agent sync complete",
		slog.Int("active", result.Active),
		slog.Int("retired", result.Retired),
		slog.Int("already_retired", result.AlreadyRetired),
	)

	return result, nil
}

// syncCore performs the three-phase sync (upsert / retire / propagate)
// and returns the populated result. Separated so SyncToTable's outer
// orchestration (timing, metrics, structured log) doesn't tangle with
// the actual reconciliation steps.
func syncCore(ctx context.Context, r *Registry, store *Store, logger *slog.Logger) (SyncResult, error) {
	registered := r.All()
	registeredNames := namesSet(registered)

	result, err := upsertAll(ctx, store, registered)
	if err != nil {
		return result, err
	}
	if err := retireAbsent(ctx, store, registeredNames, &result, logger); err != nil {
		return result, err
	}
	if err := propagateStatusBack(ctx, store, r, registeredNames, logger); err != nil {
		return result, err
	}
	return result, nil
}

// recordSyncMetrics emits a single counter + histogram observation for a
// SyncToTable run. mp may be nil for tests that don't care about
// observability; in that case the call is a no-op. Instrument creation
// failure is logged but not fatal — startup must not fail because metrics
// wiring broke.
func recordSyncMetrics(ctx context.Context, mp metric.MeterProvider, startedAt time.Time, runErr error, logger *slog.Logger) {
	if mp == nil {
		return
	}
	meter := mp.Meter("github.com/Koopa0/koopa/internal/agent")
	attempts, err := meter.Int64Counter(
		"agent.registry.sync.attempts",
		metric.WithDescription("Number of agent registry sync runs by outcome"),
	)
	if err != nil {
		logger.Warn("agent sync metrics: counter create failed", "error", err)
		return
	}
	duration, err := meter.Float64Histogram(
		"agent.registry.sync.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of agent registry sync"),
	)
	if err != nil {
		logger.Warn("agent sync metrics: histogram create failed", "error", err)
		return
	}
	outcome := "success"
	if runErr != nil {
		outcome = "failure"
	}
	attrs := metric.WithAttributes(attribute.String("outcome", outcome))
	attempts.Add(ctx, 1, attrs)
	duration.Record(ctx, time.Since(startedAt).Seconds(), attrs)
}

func namesSet(agents []Agent) map[Name]struct{} {
	out := make(map[Name]struct{}, len(agents))
	for i := range agents {
		out[agents[i].Name] = struct{}{}
	}
	return out
}

// upsertAll writes every registered agent as active in one round trip.
// Returns a partially populated SyncResult with Active count;
// Retired/AlreadyRetired are filled by retireAbsent.
func upsertAll(ctx context.Context, store *Store, registered []Agent) (SyncResult, error) {
	var result SyncResult
	if len(registered) == 0 {
		return result, nil
	}
	if err := store.UpsertAll(ctx, registered); err != nil {
		return result, fmt.Errorf("agent sync: upsert: %w", err)
	}
	result.Active = len(registered)
	return result, nil
}

// retireAbsent lists the current DB state and marks as retired, in one
// round trip, every row whose name is not in the registered set.
func retireAbsent(ctx context.Context, store *Store, registeredNames map[Name]struct{}, result *SyncResult, logger *slog.Logger) error {
	rows, err := store.List(ctx)
	if err != nil {
		return fmt.Errorf("agent sync: list: %w", err)
	}
	var toRetire []Name
	for _, row := range rows {
		if _, stillRegistered := registeredNames[row.Name]; stillRegistered {
			continue
		}
		if row.Status == StatusRetired {
			result.AlreadyRetired++
			continue
		}
		toRetire = append(toRetire, row.Name)
		logger.Warn("agent retired",
			slog.String("agent", string(row.Name)),
			slog.String("display_name", row.DisplayName),
			slog.String("reason", "absent from BuiltinAgents"),
		)
	}
	if len(toRetire) == 0 {
		return nil
	}
	if err := store.RetireAll(ctx, toRetire); err != nil {
		return fmt.Errorf("agent sync: retire: %w", err)
	}
	result.Retired = len(toRetire)
	return nil
}

// propagateStatusBack re-lists and copies DB retirement state into the
// in-memory registry so callers do not need a live DB lookup.
func propagateStatusBack(ctx context.Context, store *Store, r *Registry, registeredNames map[Name]struct{}, logger *slog.Logger) error {
	rows, err := store.List(ctx)
	if err != nil {
		return fmt.Errorf("agent sync: post-list: %w", err)
	}
	for _, row := range rows {
		if _, stillRegistered := registeredNames[row.Name]; !stillRegistered {
			continue
		}
		if row.Status == StatusRetired {
			// A name that IS in BuiltinAgents() but the DB still shows retired
			// should not happen after upsertAll (Upsert forces status=active).
			// Log loudly but do not fail — the next startup will correct it.
			logger.Error("agent sync inconsistency: registered agent shows retired in DB",
				slog.String("agent", string(row.Name)),
			)
		}
		r.SetStatus(row.Name, row.Status)
	}
	return nil
}
