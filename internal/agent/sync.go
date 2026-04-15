package agent

import (
	"context"
	"fmt"
	"log/slog"
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
//     the DB reports as retired, so Authorize() picks up retirement without
//     requiring a live DB lookup on every call.
//
// The function takes a context with a short timeout so a slow or unresponsive
// DB does not hang startup indefinitely — the caller is expected to provide
// one.
func SyncToTable(ctx context.Context, r *Registry, store *Store, logger *slog.Logger) (SyncResult, error) {
	if r == nil || store == nil {
		return SyncResult{}, fmt.Errorf("agent sync: registry and store must be non-nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

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

	logger.Info("agent sync complete",
		slog.Int("active", result.Active),
		slog.Int("retired", result.Retired),
		slog.Int("already_retired", result.AlreadyRetired),
	)

	return result, nil
}

func namesSet(agents []Agent) map[Name]struct{} {
	out := make(map[Name]struct{}, len(agents))
	for i := range agents {
		out[agents[i].Name] = struct{}{}
	}
	return out
}

// upsertAll writes every registered agent as active. Returns a partially
// populated SyncResult with Active count; Retired/AlreadyRetired are filled
// by retireAbsent.
func upsertAll(ctx context.Context, store *Store, registered []Agent) (SyncResult, error) {
	var result SyncResult
	for i := range registered {
		a := &registered[i]
		if err := store.Upsert(ctx, a); err != nil {
			return result, fmt.Errorf("agent sync: upsert %s: %w", a.Name, err)
		}
		result.Active++
	}
	return result, nil
}

// retireAbsent lists the current DB state and marks as retired any row
// whose name is not in the registered set.
func retireAbsent(ctx context.Context, store *Store, registeredNames map[Name]struct{}, result *SyncResult, logger *slog.Logger) error {
	rows, err := store.List(ctx)
	if err != nil {
		return fmt.Errorf("agent sync: list: %w", err)
	}
	for _, row := range rows {
		if _, stillRegistered := registeredNames[row.Name]; stillRegistered {
			continue
		}
		if row.Status == StatusRetired {
			result.AlreadyRetired++
			continue
		}
		if retireErr := store.Retire(ctx, row.Name); retireErr != nil {
			return fmt.Errorf("agent sync: retire %s: %w", row.Name, retireErr)
		}
		logger.Warn("agent retired",
			slog.String("agent", string(row.Name)),
			slog.String("display_name", row.DisplayName),
			slog.String("reason", "absent from BuiltinAgents"),
		)
		result.Retired++
	}
	return nil
}

// propagateStatusBack re-lists and copies DB retirement state into the
// in-memory registry so Authorize() does not need a live DB lookup.
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
