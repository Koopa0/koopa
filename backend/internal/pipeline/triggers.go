package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
	"github.com/koopa0/blog-backend/internal/feed"
)

// collectRequest is the optional request body for POST /api/pipeline/collect.
type collectRequest struct {
	Schedule string `json:"schedule"`
}

// Collect handles POST /api/pipeline/collect.
// When a schedule is provided, fetches enabled feeds for that schedule only.
// When no schedule is provided, fetches all enabled feeds.
// bg is the facade's goBackground function for launching tracked background goroutines.
func (tr *Triggers) Collect(w http.ResponseWriter, r *http.Request, bg bgFunc) {
	if tr.collector == nil || tr.feeds == nil {
		api.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "collector not configured")
		return
	}

	var schedule string
	if r.Body != nil && r.ContentLength > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req collectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.Schedule != "" {
			schedule = req.Schedule
		}
	}

	var (
		feeds []feed.Feed
		err   error
	)
	if schedule != "" {
		feeds, err = tr.feeds.EnabledFeedsBySchedule(r.Context(), schedule)
	} else {
		schedule = "all"
		feeds, err = tr.feeds.EnabledFeeds(r.Context())
	}
	if err != nil {
		tr.logger.Error("listing feeds for collect", "schedule", schedule, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list feeds")
		return
	}

	// respond 202 immediately, collect in background
	w.WriteHeader(http.StatusAccepted)

	bg("collect", func() {
		tr.collectFeeds(context.WithoutCancel(r.Context()), feeds, schedule)
	})
}

// collectFeeds fetches each feed and stores new items.
func (tr *Triggers) collectFeeds(ctx context.Context, feeds []feed.Feed, schedule string) {
	var totalNew int
	for i := range feeds {
		f := &feeds[i]
		ids, err := tr.collector.FetchFeed(ctx, f)
		if err != nil {
			tr.logger.Error("collecting feed", "feed_id", f.ID, "feed_name", f.Name, "error", err)
			continue
		}
		totalNew += len(ids)
	}
	tr.logger.Info("collect pipeline complete",
		"schedule", schedule,
		"feeds_count", len(feeds),
		"new_items", totalNew,
	)
}

// NotionSync handles POST /api/pipeline/notion-sync — full Notion sync.
// bg is the facade's goBackground function for launching tracked background goroutines.
func (tr *Triggers) NotionSync(w http.ResponseWriter, r *http.Request, bg bgFunc) {
	if tr.notionSync == nil {
		api.Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "notion sync not configured")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`)
	bg("notion-sync", func() {
		ctx := context.WithoutCancel(r.Context())
		tr.notionSync.SyncAll(ctx)
	})
}

// Reconcile handles POST /api/pipeline/reconcile — full Obsidian + Notion reconciliation.
// bg is the facade's goBackground function for launching tracked background goroutines.
func (tr *Triggers) Reconcile(w http.ResponseWriter, r *http.Request, bg bgFunc) {
	if tr.reconciler == nil {
		api.Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "reconciler not configured")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`)
	bg("reconcile", func() {
		// Detach from HTTP request lifecycle; reconciler calls external APIs.
		ctx := context.WithoutCancel(r.Context())
		if err := tr.reconciler.Run(ctx); err != nil {
			tr.logger.Error("full reconciliation failed", "error", err)
		}
	})
}

// Generate handles POST /api/pipeline/generate.
func (tr *Triggers) Generate(w http.ResponseWriter, _ *http.Request) {
	api.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "not implemented")
}

// digestRequest is the request body for POST /api/pipeline/digest.
type digestRequest struct {
	StartDate string `json:"start_date"` // YYYY-MM-DD
	EndDate   string `json:"end_date"`   // YYYY-MM-DD
}

// Digest handles POST /api/pipeline/digest.
// Submits a digest-generate flow job for the given date range.
func (tr *Triggers) Digest(w http.ResponseWriter, r *http.Request) {
	var req digestRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.StartDate == "" || req.EndDate == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "start_date and end_date are required")
		return
	}

	input, err := json.Marshal(req)
	if err != nil {
		tr.logger.Error("marshaling digest input", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	if err := tr.jobs.Submit(r.Context(), "digest-generate", input, nil); err != nil {
		tr.logger.Error("submitting digest-generate", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to submit digest job")
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`) // best-effort
}

// bookmarkRequest is the request body for POST /api/pipeline/bookmark.
type bookmarkRequest struct {
	CollectedDataID string `json:"collected_data_id"`
}

// Bookmark handles POST /api/pipeline/bookmark.
// Submits a bookmark-generate flow for the given collected data.
func (tr *Triggers) Bookmark(w http.ResponseWriter, r *http.Request) {
	var req bookmarkRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if _, err := uuid.Parse(req.CollectedDataID); err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid collected_data_id")
		return
	}

	input, err := json.Marshal(req)
	if err != nil {
		tr.logger.Error("marshaling bookmark input", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	if err := tr.jobs.Submit(r.Context(), "bookmark-generate", input, nil); err != nil {
		tr.logger.Error("submitting bookmark-generate", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to submit bookmark job")
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`) // best-effort
}
