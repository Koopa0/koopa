package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/koopa0/blog-backend/internal/activity"
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
func (h *Handler) Collect(w http.ResponseWriter, r *http.Request) {
	if h.collector == nil || h.feeds == nil {
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
		feeds, err = h.feeds.EnabledFeedsBySchedule(r.Context(), schedule)
	} else {
		schedule = "all"
		feeds, err = h.feeds.EnabledFeeds(r.Context())
	}
	if err != nil {
		h.logger.Error("listing feeds for collect", "schedule", schedule, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list feeds")
		return
	}

	// respond 202 immediately, collect in background
	w.WriteHeader(http.StatusAccepted)

	h.goBackground("collect", func() {
		h.collectFeeds(context.WithoutCancel(r.Context()), feeds, schedule)
	})
}

// collectFeeds fetches each feed and stores new items.
func (h *Handler) collectFeeds(ctx context.Context, feeds []feed.Feed, schedule string) {
	var totalNew int
	for i := range feeds {
		f := feeds[i]
		ids, err := h.collector.FetchFeed(ctx, f)
		if err != nil {
			h.logger.Error("collecting feed", "feed_id", f.ID, "feed_name", f.Name, "error", err)
			continue
		}
		totalNew += len(ids)
	}
	h.logger.Info("collect pipeline complete",
		"schedule", schedule,
		"feeds_count", len(feeds),
		"new_items", totalNew,
	)
}

// NotionSync handles POST /api/pipeline/notion-sync — full Notion sync.
func (h *Handler) NotionSync(w http.ResponseWriter, r *http.Request) {
	if h.notionSync == nil {
		api.Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "notion sync not configured")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`)
	h.goBackground("notion-sync", func() {
		ctx := context.WithoutCancel(r.Context())
		h.notionSync.SyncAll(ctx)
	})
}

// Reconcile handles POST /api/pipeline/reconcile — full Obsidian + Notion reconciliation.
func (h *Handler) Reconcile(w http.ResponseWriter, r *http.Request) {
	if h.reconciler == nil {
		api.Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "reconciler not configured")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`)
	h.goBackground("reconcile", func() {
		// Detach from HTTP request lifecycle; reconciler calls external APIs.
		ctx := context.WithoutCancel(r.Context())
		if err := h.reconciler.Run(ctx); err != nil {
			h.logger.Error("full reconciliation failed", "error", err)
		}
	})
}

// notionURLPattern extracts 32-character hex Notion page IDs from URLs.
var notionURLPattern = regexp.MustCompile(`https?://(?:www\.)?notion\.so/\S*?([0-9a-f]{32})\b`)

// handlePullRequest routes pull_request webhook events.
func (h *Handler) handlePullRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	var event PullRequestEvent
	if err := json.Unmarshal(body, &event); err != nil {
		h.logger.Error("parsing pull_request event", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// only process merged PRs (action=closed + merged=true)
	if event.Action != "closed" || !event.PullRequest.Merged {
		w.WriteHeader(http.StatusOK)
		return
	}

	if h.notionTasks == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	// respond 202 immediately, process in background
	w.WriteHeader(http.StatusAccepted)

	h.goBackground("pr-merge", func() {
		ctx := context.WithoutCancel(r.Context())
		h.handlePRMerge(ctx, &event)
	})
}

// maxNotionUpdatesPerPR caps the number of Notion pages updated per PR merge
// to bound goroutine lifetime and rate-limiter pressure.
const maxNotionUpdatesPerPR = 10

// handlePRMerge extracts Notion page IDs from the PR body and marks them as Done.
func (h *Handler) handlePRMerge(ctx context.Context, event *PullRequestEvent) {
	matches := notionURLPattern.FindAllStringSubmatch(event.PullRequest.Body, -1)
	if len(matches) == 0 {
		return
	}

	// deduplicate page IDs (a PR body might reference the same page multiple times)
	seen := make(map[string]bool, len(matches))
	for _, m := range matches {
		pageID := m[1]
		if seen[pageID] {
			continue
		}
		if len(seen) >= maxNotionUpdatesPerPR {
			h.logger.Warn("PR body exceeds max Notion page ID limit, skipping remaining",
				"limit", maxNotionUpdatesPerPR,
				"pr", event.PullRequest.Number,
			)
			break
		}
		seen[pageID] = true

		// format as UUID: 8-4-4-4-12
		formattedID := fmt.Sprintf("%s-%s-%s-%s-%s",
			pageID[:8], pageID[8:12], pageID[12:16], pageID[16:20], pageID[20:])

		if err := h.notionTasks.UpdatePageStatus(ctx, formattedID, "Done"); err != nil {
			h.logger.Error("updating notion task status",
				"page_id", formattedID,
				"repo", event.Repository.FullName,
				"pr", event.PullRequest.Number,
				"error", err,
			)
			continue
		}
		h.logger.Info("notion task marked done",
			"page_id", formattedID,
			"repo", event.Repository.FullName,
			"pr", event.PullRequest.Number,
		)
	}
}

// zeroSHA is the all-zeros SHA that GitHub sends for new branch creation.
const zeroSHA = "0000000000000000000000000000000000000000"

// handleProjectTrack submits a project-track flow job and records an activity
// event for non-Obsidian repos.
func (h *Handler) handleProjectTrack(w http.ResponseWriter, r *http.Request, event *PushEvent) {
	// collect commit messages
	messages := make([]string, 0, len(event.Commits))
	for _, c := range event.Commits {
		messages = append(messages, c.Message)
	}
	if len(messages) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	// respond 202 immediately, do all work in background
	w.WriteHeader(http.StatusAccepted)

	ctx := context.WithoutCancel(r.Context())
	h.goBackground("project-track", func() {
		// submit project-track flow job (best-effort)
		if h.jobs != nil {
			input, err := json.Marshal(map[string]any{
				"repo":    event.Repository.FullName,
				"commits": messages,
			})
			if err != nil {
				h.logger.Error("marshaling project-track input", "error", err)
			} else if err := h.jobs.Submit(ctx, "project-track", input, nil); err != nil {
				h.logger.Error("submitting project-track", "repo", event.Repository.FullName, "error", err)
			} else {
				h.logger.Info("project-track submitted", "repo", event.Repository.FullName, "commits", len(messages))
			}
		}

		// record activity event
		if h.events != nil {
			h.recordPushEvent(ctx, event)
		}
	})
}

// recordPushEvent records a push activity event, optionally enriched with diff stats.
func (h *Handler) recordPushEvent(ctx context.Context, event *PushEvent) {
	repo := event.Repository.FullName
	ref := event.Ref

	// build title from first commit message (first line only, capped at 500 chars)
	var titlePtr *string
	if len(event.Commits) > 0 {
		title := event.Commits[0].Message
		if idx := strings.IndexByte(title, '\n'); idx > 0 {
			title = title[:idx]
		}
		if len(title) > 500 {
			title = title[:500]
		}
		titlePtr = &title
	}

	// fetch diff stats from Compare API (best-effort)
	var metadata json.RawMessage
	if h.comparer != nil && event.Before != zeroSHA && isSHA(event.Before) && isSHA(event.After) {
		stats, err := h.comparer.Compare(ctx, repo, event.Before, event.After)
		if err != nil {
			h.logger.Warn("fetching diff stats", "repo", repo, "error", err)
		} else {
			stats.CommitCount = len(event.Commits)
			if data, err := json.Marshal(stats); err == nil {
				metadata = data
			}
		}
	}

	// Resolve project: try projects.repo match, fallback to raw repo name.
	// Normalize-on-write so all downstream consumers see clean slugs.
	projectName := repo
	if h.projectRepo != nil {
		if proj, projErr := h.projectRepo.ProjectByRepo(ctx, repo); projErr == nil {
			projectName = proj.Slug
		}
	}

	// source_id: use after SHA for dedup
	sourceID := event.After
	p := activity.RecordParams{
		SourceID:  &sourceID,
		Timestamp: time.Now(),
		EventType: "push",
		Source:    "github",
		Project:   &projectName,
		Repo:      &repo,
		Ref:       &ref,
		Title:     titlePtr,
		Metadata:  metadata,
	}

	if _, err := h.events.CreateEvent(ctx, &p); err != nil {
		h.logger.Error("recording push activity event", "repo", repo, "error", err)
	}
}

// Generate handles POST /api/pipeline/generate.
func (h *Handler) Generate(w http.ResponseWriter, _ *http.Request) {
	api.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "not implemented")
}

// digestRequest is the request body for POST /api/pipeline/digest.
type digestRequest struct {
	StartDate string `json:"start_date"` // YYYY-MM-DD
	EndDate   string `json:"end_date"`   // YYYY-MM-DD
}

// Digest handles POST /api/pipeline/digest.
// Submits a digest-generate flow job for the given date range.
func (h *Handler) Digest(w http.ResponseWriter, r *http.Request) {
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
		h.logger.Error("marshaling digest input", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	if err := h.jobs.Submit(r.Context(), "digest-generate", input, nil); err != nil {
		h.logger.Error("submitting digest-generate", "error", err)
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
func (h *Handler) Bookmark(w http.ResponseWriter, r *http.Request) {
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
		h.logger.Error("marshaling bookmark input", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	if err := h.jobs.Submit(r.Context(), "bookmark-generate", input, nil); err != nil {
		h.logger.Error("submitting bookmark-generate", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to submit bookmark job")
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprint(w, `{"status":"submitted"}`) // best-effort
}

// isSHA returns true if s looks like a 40-character hex SHA.
func isSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
