package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/koopa0/blog-backend/internal/auth"
	"github.com/koopa0/blog-backend/internal/budget"
	"github.com/koopa0/blog-backend/internal/collector"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/flowrun"
	"github.com/koopa0/blog-backend/internal/notion"
	"github.com/koopa0/blog-backend/internal/notify"
	"github.com/koopa0/blog-backend/internal/pipeline"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/reconcile"
	"github.com/koopa0/blog-backend/internal/spaced"
)

// cronDeps holds all dependencies needed by cron jobs.
type cronDeps struct {
	FlowrunStore     *flowrun.Store
	Runner           *flowrun.Runner
	FeedStore        *feed.Store
	FeedCollector    *collector.Collector
	TokenBudget      *budget.Budget
	AuthStore        *auth.Store
	SpacedStore      *spaced.Store
	ProjectStore     *project.Store
	NotionClient     *notion.Client
	NotionSourceStore *notion.Store
	NotionHandler    *notion.Handler
	PipelineHandler  *pipeline.Handler
	Reconciler       *reconcile.Reconciler
	Notifier         notify.Notifier
	NotionAPIKey     string
	TaipeiLoc        *time.Location
	Logger           *slog.Logger
}

// setupCrons registers all cron jobs and returns the started scheduler.
// Caller must defer cronScheduler.Stop().
func setupCrons(deps cronDeps) (*cron.Cron, error) {
	c := cron.New(cron.WithLocation(deps.TaipeiLoc))

	// retry failed/stuck flow runs every 2 minutes
	if _, err := c.AddFunc("@every 2m", cronRetryFlows(deps)); err != nil {
		return nil, fmt.Errorf("adding retry cron: %w", err)
	}

	// feed collection (with overlap guard)
	var collectRunning atomic.Bool
	collectFn := cronCollectFeeds(deps, &collectRunning)
	if _, err := c.AddFunc("0 */4 * * *", func() { collectFn(feed.ScheduleHourly4, "hourly_4") }); err != nil {
		return nil, fmt.Errorf("adding hourly_4 cron: %w", err)
	}
	if _, err := c.AddFunc("0 6 * * *", func() { collectFn(feed.ScheduleDaily, "daily") }); err != nil {
		return nil, fmt.Errorf("adding daily cron: %w", err)
	}
	if _, err := c.AddFunc("0 6 * * 1", func() { collectFn(feed.ScheduleWeekly, "weekly") }); err != nil {
		return nil, fmt.Errorf("adding weekly cron: %w", err)
	}

	// daily resets
	if _, err := c.AddFunc("0 0 * * *", func() {
		deps.TokenBudget.Reset()
		deps.Logger.Info("cron: daily token budget reset")
	}); err != nil {
		return nil, fmt.Errorf("adding budget reset cron: %w", err)
	}
	if _, err := c.AddFunc("0 1 * * *", cronCleanExpiredTokens(deps)); err != nil {
		return nil, fmt.Errorf("adding token cleanup cron: %w", err)
	}

	// flow submissions
	for _, job := range []struct {
		schedule string
		flow     string
		timeout  time.Duration
	}{
		{"30 7 * * *", "morning-brief", 2 * time.Minute},
		{"0 9 * * 1", "weekly-review", 3 * time.Minute},
		{"0 3 * * 1", "content-strategy", 3 * time.Minute},
		{"0 23 * * *", "daily-dev-log", 2 * time.Minute},
	} {
		job := job // capture
		if _, err := c.AddFunc(job.schedule, func() {
			ctx, cancel := context.WithTimeout(context.Background(), job.timeout)
			defer cancel()
			if err := deps.Runner.Submit(ctx, job.flow, nil, nil); err != nil {
				deps.Logger.Error("cron: submitting flow", "flow", job.flow, "error", err)
			}
		}); err != nil {
			return nil, fmt.Errorf("adding %s cron: %w", job.flow, err)
		}
	}

	// build-log generation: per active project with repo (Monday 10:00)
	if _, err := c.AddFunc("0 10 * * 1", cronBuildLogs(deps)); err != nil {
		return nil, fmt.Errorf("adding build-log cron: %w", err)
	}

	// spaced repetition reminder (09:00 daily)
	if _, err := c.AddFunc("0 9 * * *", cronSpacedReminder(deps)); err != nil {
		return nil, fmt.Errorf("adding spaced reminder cron: %w", err)
	}

	// reconciliation (Sunday 04:00)
	if _, err := c.AddFunc("0 4 * * 0", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := deps.Reconciler.Run(ctx); err != nil {
			deps.Logger.Error("cron: reconciliation failed", "error", err)
		}
	}); err != nil {
		return nil, fmt.Errorf("adding reconciliation cron: %w", err)
	}

	// hourly full sync — GitHub + Notion (at :15 past each hour)
	var syncRunning atomic.Bool
	if _, err := c.AddFunc("15 * * * *", func() {
		if !syncRunning.CompareAndSwap(false, true) {
			deps.Logger.Info("cron: skipping hourly sync, previous run still active")
			return
		}
		defer syncRunning.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		deps.PipelineHandler.SyncAllFromGitHub(ctx)
		deps.NotionHandler.SyncAll(ctx)
	}); err != nil {
		return nil, fmt.Errorf("adding hourly sync cron: %w", err)
	}

	c.Start()
	return c, nil
}

func cronRetryFlows(d cronDeps) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		runs, err := d.FlowrunStore.RetryableRuns(ctx)
		if err != nil {
			d.Logger.Error("cron: scanning retryable flow runs", "error", err)
			return
		}
		for _, r := range runs {
			d.Runner.Requeue(r.ID)
		}
		if len(runs) > 0 {
			d.Logger.Info("cron: requeued flow runs", "count", len(runs))
		}
	}
}

func cronCollectFeeds(d cronDeps, running *atomic.Bool) func(schedule, label string) {
	return func(schedule, label string) {
		if !running.CompareAndSwap(false, true) {
			d.Logger.Info("cron: skipping " + label + ", previous run still active")
			return
		}
		defer running.Store(false)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		feeds, err := d.FeedStore.EnabledFeedsBySchedule(ctx, schedule)
		if err != nil {
			d.Logger.Error("cron: listing "+label+" feeds", "error", err)
			return
		}
		var totalNew int
		for _, f := range feeds {
			ids, fetchErr := d.FeedCollector.FetchFeed(ctx, f)
			if fetchErr != nil {
				d.Logger.Error("cron: collecting feed", "feed_id", f.ID, "error", fetchErr)
				continue
			}
			totalNew += len(ids)
		}
		if len(feeds) > 0 {
			d.Logger.Info("cron: "+label+" collect complete", "feeds", len(feeds), "new_items", totalNew)
		}
	}
}

func cronCleanExpiredTokens(d cronDeps) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := d.AuthStore.DeleteExpiredTokens(ctx); err != nil {
			d.Logger.Error("cron: deleting expired tokens", "error", err)
		} else {
			d.Logger.Info("cron: expired tokens cleaned up")
		}
	}
}

func cronBuildLogs(d cronDeps) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		slugs, err := d.ProjectStore.ActiveSlugsWithRepo(ctx)
		if err != nil {
			d.Logger.Error("cron: listing active projects for build-log", "error", err)
			return
		}
		for _, slug := range slugs {
			input, _ := json.Marshal(map[string]any{"project_slug": slug, "days": 7}) //nolint:errchkjson // static map
			if submitErr := d.Runner.Submit(ctx, "build-log-generate", input, nil); submitErr != nil {
				d.Logger.Error("cron: submitting build-log", "project", slug, "error", submitErr)
			}
		}
		if len(slugs) > 0 {
			d.Logger.Info("cron: build-log submitted", "projects", len(slugs))
		}
	}
}

func cronSpacedReminder(d cronDeps) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		count, err := d.SpacedStore.DueCount(ctx)
		if err != nil {
			d.Logger.Error("cron: checking spaced due count", "error", err)
			return
		}
		if count == 0 {
			return
		}
		msg := fmt.Sprintf("📚 你有 %d 個筆記要複習\nhttps://koopa0.dev/admin/spaced", count)
		if sendErr := d.Notifier.Send(ctx, msg); sendErr != nil {
			d.Logger.Error("cron: sending spaced reminder", "error", sendErr)
		}
		if d.NotionAPIKey == "" {
			return
		}
		tasksSrc, lookupErr := d.NotionSourceStore.SourceByRole(ctx, notion.RoleTasks)
		if lookupErr != nil {
			return
		}
		today := time.Now().In(d.TaipeiLoc).Format("2006-01-02")
		title := fmt.Sprintf("📚 複習 %d 篇筆記", count)
		if _, createErr := d.NotionClient.CreateTask(ctx, notion.CreateTaskParams{
			DatabaseID:  tasksSrc.DatabaseID,
			Title:       title,
			DueDate:     today,
			Description: "https://koopa0.dev/admin/spaced",
		}); createErr != nil {
			d.Logger.Error("cron: creating spaced reminder task in notion", "error", createErr)
		} else {
			d.Logger.Info("cron: spaced reminder task created in notion", "count", count)
		}
	}
}
