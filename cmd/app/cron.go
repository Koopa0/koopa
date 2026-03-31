package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/activity"
	"github.com/Koopa0/koopa0.dev/internal/ai/exec"
	"github.com/Koopa0/koopa0.dev/internal/auth"
	"github.com/Koopa0/koopa0.dev/internal/budget"
	"github.com/Koopa0/koopa0.dev/internal/feed"
	"github.com/Koopa0/koopa0.dev/internal/feed/collector"
	"github.com/Koopa0/koopa0.dev/internal/notify"
	"github.com/Koopa0/koopa0.dev/internal/notion"
	"github.com/Koopa0/koopa0.dev/internal/project"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// retryFlows requeues failed/stuck flow runs.
func retryFlows(appCtx context.Context, store *exec.Store, runner *exec.Runner, notifier notify.Notifier, logger *slog.Logger) func() {
	return func() {
		ctx, cancel := context.WithTimeout(appCtx, 1*time.Minute)
		defer cancel()
		runs, err := store.RetryableRuns(ctx)
		if err != nil {
			logger.Error("cron: scanning retryable flow runs", "error", err)
			alertCron(notifier, logger, "flow-retry-scan", err)
			return
		}
		for i := range runs {
			runner.Requeue(runs[i].ID)
		}
		if len(runs) > 0 {
			logger.Info("cron: requeued flow runs", "count", len(runs))
		}
	}
}

// collectFeeds fetches RSS feeds with an overlap guard.
func collectFeeds(
	appCtx context.Context,
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

		ctx, cancel := context.WithTimeout(appCtx, 5*time.Minute)
		defer cancel()

		feeds, err := feedStore.EnabledFeedsBySchedule(ctx, schedule)
		if err != nil {
			logger.Error("cron: listing "+label+" feeds", "error", err)
			alertCron(notifier, logger, "feed-collect-"+label, err)
			return
		}
		var totalNew int
		for i := range feeds {
			ids, fetchErr := coll.FetchFeed(ctx, &feeds[i])
			if fetchErr != nil {
				logger.Error("cron: collecting feed", "feed_id", feeds[i].ID, "error", fetchErr)
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
	appCtx context.Context,
	execStore *exec.Store,
	feedStore *feed.Store,
	runner *exec.Runner,
	logger *slog.Logger,
) func() {
	return func() {
		ctx, cancel := context.WithTimeout(appCtx, 3*time.Minute)
		defer cancel()

		weekAgo := time.Now().AddDate(0, 0, -7)

		var issues []string

		stats, err := execStore.FailureStats(ctx, weekAgo)
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
func submitBuildLogs(appCtx context.Context, projectStore *project.Store, runner *exec.Runner, logger *slog.Logger) func() {
	return func() {
		ctx, cancel := context.WithTimeout(appCtx, 3*time.Minute)
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

// resetBudget resets the daily token budget counter.
func resetBudget(b *budget.Budget, logger *slog.Logger) func() {
	return func() {
		b.Reset()
		logger.Info("cron: daily token budget reset")
	}
}

// cleanupExpiredTokens deletes expired auth tokens.
func cleanupExpiredTokens(appCtx context.Context, store *auth.Store, logger *slog.Logger) func() {
	return func() {
		ctx, cancel := context.WithTimeout(appCtx, 30*time.Second)
		defer cancel()
		if err := store.DeleteExpiredTokens(ctx); err != nil {
			logger.Error("cron: deleting expired tokens", "error", err)
		}
	}
}

// retentionTimeout is the maximum duration for a single retention cleanup job.
const retentionTimeout = 1 * time.Minute

// retentionFunc returns a cron func that deletes old records via the provided delete function.
func retentionFunc(appCtx context.Context, name string, deleteFn func(ctx context.Context) (int64, error), logger *slog.Logger) func() {
	return func() {
		ctx, cancel := context.WithTimeout(appCtx, retentionTimeout)
		defer cancel()
		n, err := deleteFn(ctx)
		if err != nil {
			logger.Error("cron: "+name, "error", err)
		} else if n > 0 {
			logger.Info("cron: "+name, "count", n)
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

// dailyReset implements the 4-step My Day reset + recurring task advance.
// Runs at 04:00 Asia/Taipei daily. Steps:
// ① Log incomplete My Day tasks → ② Clear all My Day → ③ Skip + advance overdue → ④ Auto-populate
func dailyReset(
	appCtx context.Context,
	taskStore *task.Store,
	activityStore *activity.Store,
	notionClient *notion.Client,
	running *atomic.Bool,
	loc *time.Location,
	logger *slog.Logger,
) func() {
	return func() {
		if !running.CompareAndSwap(false, true) {
			logger.Info("cron: skipping daily-reset, previous run still active")
			return
		}
		defer running.Store(false)

		ctx, cancel := context.WithTimeout(appCtx, 5*time.Minute)
		defer cancel()

		now := time.Now().In(loc)
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
		yesterday := today.AddDate(0, 0, -1)

		// Step ①: Log incomplete My Day tasks as activity events
		stepLogIncomplete(ctx, taskStore, activityStore, today, yesterday, logger)

		// Step ②: Clear all My Day flags
		stepClearMyDay(ctx, taskStore, notionClient, logger)

		// Step ③: Skip detection + due date advance for overdue recurring tasks
		stepAdvanceOverdue(ctx, taskStore, notionClient, today, logger)

		// Step ④: Auto-populate My Day for recurring tasks due today
		stepPopulateMyDay(ctx, taskStore, notionClient, today, logger)

		logger.Info("cron: daily-reset complete")
	}
}

// stepLogIncomplete logs My Day tasks that were not completed as activity events.
func stepLogIncomplete(ctx context.Context, ts *task.Store, as *activity.Store, today, yesterday time.Time, logger *slog.Logger) {
	incomplete, err := ts.MyDayIncompleteTaskIDs(ctx)
	if err != nil {
		logger.Error("cron: step①: listing incomplete my day tasks", "error", err)
		return
	}

	// Check which tasks were actually completed today (don't false-flag 03:55 completions)
	todayStart := today
	var logged int
	for _, t := range incomplete {
		// Skip if task was completed today via activity_events
		if as != nil {
			prefix := fmt.Sprintf("task-complete-%s-", t.ID)
			count, _ := as.CountEventsByPrefix(ctx, "task_completed", prefix, todayStart)
			if count > 0 {
				continue
			}
		}

		// Log as incomplete activity event
		if as != nil {
			evTitle := fmt.Sprintf("My Day incomplete: %s", t.Title)
			sourceID := fmt.Sprintf("myday-incomplete-%s-%s", t.ID, yesterday.Format(time.DateOnly))
			params := &activity.RecordParams{
				SourceID:  &sourceID,
				Timestamp: yesterday,
				Source:    "cron",
				EventType: "my_day_incomplete",
				Title:     &evTitle,
			}
			//nolint:errcheck // best-effort
			as.CreateEvent(ctx, params)
			logged++
		}
	}
	if logged > 0 {
		logger.Info("cron: step①: logged incomplete my day tasks", "count", logged)
	}
}

// stepClearMyDay clears all My Day flags and syncs to Notion.
func stepClearMyDay(ctx context.Context, ts *task.Store, nc *notion.Client, logger *slog.Logger) {
	// Sync to Notion first (best-effort)
	if nc != nil {
		myDayTasks, err := ts.MyDayTasksWithNotionPageID(ctx)
		if err != nil {
			logger.Error("cron: step②: listing notion my day tasks", "error", err)
		} else {
			for _, t := range myDayTasks {
				props := map[string]any{"My Day": map[string]any{"checkbox": false}}
				if syncErr := nc.UpdatePageProperties(ctx, t.NotionPageID, props); syncErr != nil {
					logger.Warn("cron: step②: notion sync failed", "page_id", t.NotionPageID, "error", syncErr)
				}
			}
		}
	}

	n, err := ts.ClearAllMyDay(ctx)
	if err != nil {
		logger.Error("cron: step②: clearing my day", "error", err)
		return
	}
	if n > 0 {
		logger.Info("cron: step②: cleared my day flags", "count", n)
	}
}

// stepAdvanceOverdue detects skips and advances due dates for overdue recurring tasks.
func stepAdvanceOverdue(ctx context.Context, ts *task.Store, nc *notion.Client, today time.Time, logger *slog.Logger) {
	overdue, err := ts.OverdueRecurringTasks(ctx, today)
	if err != nil {
		logger.Error("cron: step③: listing overdue recurring tasks", "error", err)
		return
	}

	for i := range overdue {
		t := &overdue[i]

		// Log missed occurrences
		missed := t.MissedOccurrences(today)
		for _, skippedDate := range missed {
			if logErr := ts.LogSkip(ctx, t.ID, *t.Due, skippedDate, "auto-expired"); logErr != nil {
				logger.Error("cron: step③: logging skip", "task_id", t.ID, "skipped_date", skippedDate, "error", logErr)
			}
		}

		// Advance to next cycle date
		nextDue := t.NextCycleDateOnOrAfter(today)
		if nextDue == nil {
			logger.Warn("cron: step③: cannot calculate next due", "task_id", t.ID)
			continue
		}

		if err := ts.UpdateDue(ctx, t.ID, *nextDue); err != nil {
			logger.Error("cron: step③: advancing due date", "task_id", t.ID, "error", err)
			continue
		}

		// Sync to Notion
		if t.NotionPageID != nil && nc != nil {
			props := map[string]any{
				"Due": map[string]any{"date": map[string]string{"start": nextDue.Format(time.DateOnly)}},
			}
			if syncErr := nc.UpdatePageProperties(ctx, *t.NotionPageID, props); syncErr != nil {
				logger.Warn("cron: step③: notion due sync failed", "task_id", t.ID, "error", syncErr)
			}
		}

		logger.Info("cron: step③: advanced recurring task",
			"task_id", t.ID,
			"title", t.Title,
			"old_due", t.Due.Format(time.DateOnly),
			"new_due", nextDue.Format(time.DateOnly),
			"skips_logged", len(missed),
		)
	}
}

// stepPopulateMyDay sets my_day=true for recurring tasks due today and syncs to Notion.
func stepPopulateMyDay(ctx context.Context, ts *task.Store, nc *notion.Client, today time.Time, logger *slog.Logger) {
	tasks, err := ts.RecurringTasksDueToday(ctx, today)
	if err != nil {
		logger.Error("cron: step④: listing recurring tasks due today", "error", err)
		return
	}

	var set int
	for i := range tasks {
		t := &tasks[i]
		if t.MyDay {
			continue // already set
		}

		if myDayErr := ts.UpdateMyDay(ctx, t.ID, true); myDayErr != nil {
			logger.Error("cron: step④: setting my day", "task_id", t.ID, "error", myDayErr)
			continue
		}

		// Sync to Notion
		if t.NotionPageID != nil && nc != nil {
			props := map[string]any{"My Day": map[string]any{"checkbox": true}}
			if syncErr := nc.UpdatePageProperties(ctx, *t.NotionPageID, props); syncErr != nil {
				logger.Warn("cron: step④: notion my day sync failed", "task_id", t.ID, "error", syncErr)
			}
		}
		set++
	}
	if set > 0 {
		logger.Info("cron: step④: populated my day", "count", set)
	}
}
