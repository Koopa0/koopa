package notion

import (
	"context"
	"errors"
	"time"
)

// SyncAll fetches all pages from configured Notion databases and upserts them.
// Uses QueryDataSource to get full page data in bulk, avoiding per-page API calls.
// Used by the hourly cron to catch any missed webhook events.
func (h *Handler) SyncAll(ctx context.Context) {
	targets := h.syncTargets()
	var synced, failed int
	for _, t := range targets {
		s, f := h.syncByRole(ctx, t)
		synced += s
		failed += f
	}
	h.logger.Info("notion sync: complete", "synced", synced, "failed", failed)
}

// SyncRole syncs only the specified role's Notion database.
// Used when a source is created or its role is changed.
func (h *Handler) SyncRole(ctx context.Context, role string) {
	for _, t := range h.syncTargets() {
		if t.role == role {
			s, f := h.syncByRole(ctx, t)
			h.logger.Info("notion sync role: complete", "role", role, "synced", s, "failed", f)
			return
		}
	}
	h.logger.Warn("notion sync role: unknown role", "role", role)
}

// SyncRoleAsync launches SyncRole in a tracked background goroutine.
// Detaches from the caller's context (which may be an HTTP request) so the
// sync outlives the request, then applies syncRoleTimeout to bound execution.
func (h *Handler) SyncRoleAsync(ctx context.Context, role string) {
	h.bgWg.Go(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), syncRoleTimeout) //nolint:govet // intentional context narrowing for background sync
		defer cancel()
		h.SyncRole(ctx, role)
	})
}

// syncTargets builds the list of role-specific sync operations.
func (h *Handler) syncTargets() []syncTarget {
	var targets []syncTarget
	if h.projectArchiver != nil {
		targets = append(targets, syncTarget{
			role:          RoleProjects,
			syncFn:        h.syncProjectFromResult,
			archiveOrphan: h.projectArchiver.ArchiveOrphanNotion,
		})
	}
	if h.goalArchiver != nil {
		targets = append(targets, syncTarget{
			role:          RoleGoals,
			syncFn:        h.syncGoalFromResult,
			archiveOrphan: h.goalArchiver.ArchiveOrphanNotion,
		})
	}
	if h.taskArchiver != nil {
		targets = append(targets, syncTarget{
			role:          RoleTasks,
			syncFn:        h.syncTaskFromResult,
			archiveOrphan: h.taskArchiver.ArchiveOrphanNotion,
		})
	}
	return targets
}

// syncByRole runs a single role sync: query data source, upsert pages, archive orphans.
// Skips the sync if the source was synced less than staleSyncThreshold ago.
func (h *Handler) syncByRole(ctx context.Context, t syncTarget) (synced, failed int) {
	src, err := h.store.SourceByRole(ctx, t.role)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			h.logger.Error("notion sync: looking up source", "role", t.role, "error", err)
		}
		return 0, 0
	}

	// Skip if recently synced (avoids redundant API calls on rapid restarts)
	if src.LastSyncedAt != nil && time.Since(*src.LastSyncedAt) < staleSyncThreshold {
		h.logger.Info("notion sync: skipping (recently synced)",
			"role", t.role,
			"last_synced", src.LastSyncedAt,
		)
		return 0, 0
	}

	h.logger.Info("notion sync: starting", "role", t.role, "database_id", src.DatabaseID)
	results, err := h.client.QueryDataSource(ctx, src.DatabaseID, nil)
	if err != nil {
		h.logger.Error("notion sync: querying database", "role", t.role, "error", err)
		return 0, 0
	}

	h.logger.Info("notion sync: fetched pages", "role", t.role, "count", len(results))
	activeIDs := make([]string, 0, len(results))
	for _, r := range results {
		// Skip if a webhook is actively syncing this page to avoid
		// overwriting fresh webhook data with potentially stale cron data.
		if _, busy := h.syncInFlight.LoadOrStore(r.ID, struct{}{}); busy {
			h.logger.Debug("notion sync: skipping page (webhook in progress)",
				"role", t.role, "page_id", r.ID)
			activeIDs = append(activeIDs, r.ID) // still active for orphan check
			continue
		}
		if err := t.syncFn(ctx, r); err != nil {
			h.syncInFlight.Delete(r.ID)
			h.logger.Error("notion sync: syncing page", "role", t.role, "page_id", r.ID, "error", err)
			failed++
			continue
		}
		h.syncInFlight.Delete(r.ID)
		activeIDs = append(activeIDs, r.ID)
		synced++
	}

	if len(results) > 0 && len(activeIDs) == 0 {
		h.logger.Warn("notion sync: all page syncs failed, skipping orphan archive",
			"role", t.role, "total", len(results), "failed", failed)
	}

	if archived, archErr := t.archiveOrphan(ctx, activeIDs); archErr != nil {
		h.logger.Error("notion sync: archiving orphans", "role", t.role, "error", archErr)
	} else if archived > 0 {
		h.logger.Info("notion sync: archived orphans", "role", t.role, "count", archived)
	}

	if updateErr := h.store.UpdateLastSynced(ctx, src.ID); updateErr != nil {
		h.logger.Error("notion sync: updating last_synced_at", "role", t.role, "error", updateErr)
	}

	return synced, failed
}
