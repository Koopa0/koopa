package pipeline

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/webhook"
)

// bgFunc is a callback for running work in a tracked background goroutine
// with backpressure. The Handler facade provides this to sub-structs.
type bgFunc = func(name string, fn func())

// Handle verifies the GitHub webhook signature, deduplicates deliveries,
// and routes by event type. bg is the facade's goBackground function for
// launching tracked background goroutines.
func (wr *WebhookRouter) Handle(w http.ResponseWriter, r *http.Request, bg bgFunc) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	body, err := io.ReadAll(r.Body)
	if err != nil {
		wr.logger.Error("reading webhook body", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	sig := r.Header.Get("X-Hub-Signature-256")
	if err := webhook.VerifySignature(body, sig, wr.webhookSecret); err != nil {
		wr.logger.Warn("invalid webhook signature")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// replay protection: reject duplicate deliveries
	if wr.dedup != nil {
		deliveryID := r.Header.Get("X-GitHub-Delivery")
		if deliveryID != "" && wr.dedup.Seen(deliveryID) {
			wr.logger.Warn("github webhook replay detected", "delivery_id", deliveryID)
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// route by event type
	eventType := r.Header.Get("X-GitHub-Event")
	switch eventType {
	case "pull_request":
		wr.handlePullRequest(w, r, body, bg)
		return
	case "push":
		// handled below
	default:
		w.WriteHeader(http.StatusOK)
		return
	}

	var event PushEvent
	if err := json.Unmarshal(body, &event); err != nil {
		wr.logger.Error("parsing push event", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// B2 self-loop protection: ignore pushes from the bot account.
	// This check runs AFTER HMAC verification so that an attacker cannot
	// craft a payload with Sender.Login == botLogin to bypass processing.
	if wr.botLogin != "" && event.Sender.Login == wr.botLogin {
		wr.logger.Info("ignoring push from bot", "sender", event.Sender.Login)
		w.WriteHeader(http.StatusOK)
		return
	}

	// only process pushes to main branch
	if event.Ref != "refs/heads/main" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// route: Obsidian repo → content sync, other repos → project-track
	if event.Repository.FullName != wr.obsidianRepo {
		wr.handleProjectTrack(w, r, &event, bg)
		return
	}

	// split changed files into public content (A1) and knowledge notes (B1)
	changed := event.ChangedFiles()
	removedAll := event.RemovedFiles()

	publicFiles := filterPublicMarkdown(changed)
	publicRemoved := filterPublicMarkdown(removedAll)
	knowledgeFiles := filterKnowledgeMarkdown(changed)
	knowledgeRemoved := filterKnowledgeMarkdown(removedAll)

	if len(publicFiles) == 0 && len(publicRemoved) == 0 &&
		len(knowledgeFiles) == 0 && len(knowledgeRemoved) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	// respond 202 immediately, process in background
	w.WriteHeader(http.StatusAccepted)

	cs := wr.contentSync
	bg("webhook-push", func() {
		ctx := context.WithoutCancel(r.Context())

		// A1: public content sync
		cs.syncFiles(ctx, publicFiles)
		cs.archiveRemovedFiles(ctx, publicRemoved)

		// B1: knowledge note sync
		if cs.notes != nil && cs.tags != nil {
			cs.syncKnowledgeNotes(ctx, knowledgeFiles)
			cs.archiveKnowledgeNotes(ctx, knowledgeRemoved)
		}
	})
}

// notionURLPattern extracts 32-character hex Notion page IDs from URLs.
var notionURLPattern = regexp.MustCompile(`https?://(?:www\.)?notion\.so/\S*?([0-9a-f]{32})\b`)

// handlePullRequest routes pull_request webhook events.
func (wr *WebhookRouter) handlePullRequest(w http.ResponseWriter, r *http.Request, body []byte, bg bgFunc) {
	var event PullRequestEvent
	if err := json.Unmarshal(body, &event); err != nil {
		wr.logger.Error("parsing pull_request event", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// only process merged PRs (action=closed + merged=true)
	if event.Action != "closed" || !event.PullRequest.Merged {
		w.WriteHeader(http.StatusOK)
		return
	}

	if wr.notionTasks == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	// respond 202 immediately, process in background
	w.WriteHeader(http.StatusAccepted)

	bg("pr-merge", func() {
		ctx := context.WithoutCancel(r.Context())
		wr.handlePRMerge(ctx, &event)
	})
}

// maxNotionUpdatesPerPR caps the number of Notion pages updated per PR merge
// to bound goroutine lifetime and rate-limiter pressure.
const maxNotionUpdatesPerPR = 10

// handlePRMerge extracts Notion page IDs from the PR body and marks them as Done.
func (wr *WebhookRouter) handlePRMerge(ctx context.Context, event *PullRequestEvent) {
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
			wr.logger.Warn("PR body exceeds max Notion page ID limit, skipping remaining",
				"limit", maxNotionUpdatesPerPR,
				"pr", event.PullRequest.Number,
			)
			break
		}
		seen[pageID] = true

		// format as UUID: 8-4-4-4-12
		formattedID := strings.Join([]string{
			pageID[:8], pageID[8:12], pageID[12:16], pageID[16:20], pageID[20:],
		}, "-")

		if err := wr.notionTasks.UpdatePageStatus(ctx, formattedID, "Done"); err != nil {
			wr.logger.Error("updating notion task status",
				"page_id", formattedID,
				"repo", event.Repository.FullName,
				"pr", event.PullRequest.Number,
				"error", err,
			)
			continue
		}
		wr.logger.Info("notion task marked done",
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
func (wr *WebhookRouter) handleProjectTrack(w http.ResponseWriter, r *http.Request, event *PushEvent, bg bgFunc) {
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
	bg("project-track", func() {
		// submit project-track flow job (best-effort)
		if wr.jobs != nil {
			input, err := json.Marshal(map[string]any{
				"repo":    event.Repository.FullName,
				"commits": messages,
			})
			if err != nil {
				wr.logger.Error("marshaling project-track input", "error", err)
			} else if err := wr.jobs.Submit(ctx, "project-track", input, nil); err != nil {
				wr.logger.Error("submitting project-track", "repo", event.Repository.FullName, "error", err)
			} else {
				wr.logger.Info("project-track submitted", "repo", event.Repository.FullName, "commits", len(messages))
			}
		}

		// record activity event
		if wr.events != nil {
			wr.recordPushEvent(ctx, event)
		}
	})
}

// recordPushEvent records a push activity event, optionally enriched with diff stats.
func (wr *WebhookRouter) recordPushEvent(ctx context.Context, event *PushEvent) {
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
	metadata := wr.fetchDiffMetadata(ctx, repo, event)

	// Resolve project: try projects.repo match, fallback to raw repo name.
	// Normalize-on-write so all downstream consumers see clean slugs.
	projectName := repo
	if wr.projectRepo != nil {
		if proj, projErr := wr.projectRepo.ProjectByRepo(ctx, repo); projErr == nil {
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

	if _, err := wr.events.CreateEvent(ctx, &p); err != nil {
		wr.logger.Error("recording push activity event", "repo", repo, "error", err)
	}
}

// fetchDiffMetadata fetches diff stats from the Compare API if conditions are met.
func (wr *WebhookRouter) fetchDiffMetadata(ctx context.Context, repo string, event *PushEvent) json.RawMessage {
	if wr.comparer == nil || event.Before == zeroSHA || !isSHA(event.Before) || !isSHA(event.After) {
		return nil
	}
	stats, err := wr.comparer.Compare(ctx, repo, event.Before, event.After)
	if err != nil {
		wr.logger.Warn("fetching diff stats", "repo", repo, "error", err)
		return nil
	}
	stats.CommitCount = len(event.Commits)
	data, err := json.Marshal(stats)
	if err != nil {
		return nil
	}
	return data
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
