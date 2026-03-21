package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/koopa0/blog-backend/internal/collector"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/flowrun"
	"github.com/koopa0/blog-backend/internal/notify"
	"github.com/koopa0/blog-backend/internal/project"
)

// retryFlows requeues failed/stuck flow runs.
func retryFlows(store *flowrun.Store, runner *flowrun.Runner, notifier notify.Notifier, logger *slog.Logger) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		runs, err := store.RetryableRuns(ctx)
		if err != nil {
			logger.Error("cron: scanning retryable flow runs", "error", err)
			alertCron(notifier, logger, "flow-retry-scan", err)
			return
		}
		for _, r := range runs {
			runner.Requeue(r.ID)
		}
		if len(runs) > 0 {
			logger.Info("cron: requeued flow runs", "count", len(runs))
		}
	}
}

// collectFeeds fetches RSS feeds with an overlap guard.
func collectFeeds(
	feedStore *feed.Store,
	coll *collector.Collector,
	running *atomic.Bool,
	notifier notify.Notifier,
	logger *slog.Logger,
) func(schedule, label string) {
	return func(schedule, label string) {
		if !running.CompareAndSwap(false, true) {
			logger.Info("cron: skipping " + label + ", previous run still active")
			return
		}
		defer running.Store(false)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		feeds, err := feedStore.EnabledFeedsBySchedule(ctx, schedule)
		if err != nil {
			logger.Error("cron: listing "+label+" feeds", "error", err)
			alertCron(notifier, logger, "feed-collect-"+label, err)
			return
		}
		var totalNew int
		for _, f := range feeds {
			ids, fetchErr := coll.FetchFeed(ctx, f)
			if fetchErr != nil {
				logger.Error("cron: collecting feed", "feed_id", f.ID, "error", fetchErr)
				continue
			}
			totalNew += len(ids)
		}
		if len(feeds) > 0 {
			logger.Info("cron: "+label+" collect complete", "feeds", len(feeds), "new_items", totalNew)
		}
	}
}

// submitWeeklyReview gathers system health data and submits the weekly-review flow.
func submitWeeklyReview(
	flowrunStore *flowrun.Store,
	feedStore *feed.Store,
	runner *flowrun.Runner,
	logger *slog.Logger,
) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		weekAgo := time.Now().AddDate(0, 0, -7)

		var issues []string

		stats, err := flowrunStore.FailureStats(ctx, weekAgo)
		if err != nil {
			logger.Error("cron: weekly-review health: flow stats", "error", err)
		} else {
			for _, s := range stats {
				rate := float64(s.Failed) / float64(s.Total) * 100
				if rate > 50 {
					issues = append(issues, fmt.Sprintf("flow %q 失敗率 %.0f%%（%d/%d）", s.FlowName, rate, s.Failed, s.Total))
				}
			}
		}

		feeds, err := feedStore.Feeds(ctx, nil)
		if err != nil {
			logger.Error("cron: weekly-review health: feeds", "error", err)
		} else {
			for i := range feeds {
				if feeds[i].ConsecutiveFailures >= 3 {
					issues = append(issues, fmt.Sprintf("feed %q 連續失敗 %d 次", feeds[i].Name, feeds[i].ConsecutiveFailures))
				}
			}
		}

		var input json.RawMessage
		if len(issues) > 0 {
			input, _ = json.Marshal(map[string]any{"health_issues": issues}) //nolint:errchkjson // static structure
		}

		if submitErr := runner.Submit(ctx, "weekly-review", input, nil); submitErr != nil {
			logger.Error("cron: submitting weekly-review", "error", submitErr)
		}
	}
}

// submitBuildLogs generates build logs for active projects with recent activity.
func submitBuildLogs(projectStore *project.Store, runner *flowrun.Runner, logger *slog.Logger) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		since := time.Now().AddDate(0, 0, -7)
		slugs, err := projectStore.ActiveSlugsWithRepo(ctx, since)
		if err != nil {
			logger.Error("cron: listing active projects for build-log", "error", err)
			return
		}
		for _, slug := range slugs {
			input, _ := json.Marshal(map[string]any{"project_slug": slug, "days": 7}) //nolint:errchkjson // static map
			if submitErr := runner.Submit(ctx, "build-log-generate", input, nil); submitErr != nil {
				logger.Error("cron: submitting build-log", "project", slug, "error", submitErr)
			}
		}
		if len(slugs) > 0 {
			logger.Info("cron: build-log submitted", "projects", len(slugs))
		}
	}
}

// alertCron sends a notification when a critical cron job fails.
func alertCron(notifier notify.Notifier, logger *slog.Logger, jobName string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	msg := fmt.Sprintf("[CRON ALERT] %s failed: %s", jobName, err)
	if sendErr := notifier.Send(ctx, msg); sendErr != nil {
		logger.Error("cron: sending alert notification", "job", jobName, "error", sendErr)
	}
}
