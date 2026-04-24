// scheduler.go owns the in-process periodic feed-fetcher loop. Launched
// as a background goroutine from cmd/app/main.go, it wakes every 15
// minutes, walks every schedule type (hourly → monthly), and invokes
// the collector's FetchFeed on each feed whose LastFetchedAt is older
// than the schedule's interval. Every fetch — success or failure —
// records a process_runs row via CrawlRunRecorder for observability.
//
// Single-instance assumption: there is no distributed lock here. If
// the app ever runs as multi-instance, gate this behind an
// advisory-lock or extract to a dedicated cron worker.

package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/db"
)

// scheduleOrder defines a deterministic iteration order for feed schedules,
// ordered by interval from shortest to longest. The names mirror the schema
// CHECK on feeds.schedule.
var scheduleOrder = []struct {
	name     string
	interval time.Duration
}{
	{ScheduleHourly, time.Hour},
	{ScheduleDaily, 24 * time.Hour},
	{ScheduleWeekly, 7 * 24 * time.Hour},
	{ScheduleBiweekly, 14 * 24 * time.Hour},
	{ScheduleMonthly, 30 * 24 * time.Hour},
}

// CrawlRunRecorder writes crawl run audit records. crawl is the schema's
// process_runs.kind value for internal fetch/collector runs — see
// migrations/001_initial.up.sql at process_runs.kind.
type CrawlRunRecorder interface {
	InsertCrawlRun(ctx context.Context, arg db.InsertCrawlRunParams) error
}

// Scheduler runs periodic feed fetches based on each feed's schedule.
type Scheduler struct {
	feeds    *Store
	fetcher  ManualFetcher
	recorder CrawlRunRecorder
	logger   *slog.Logger
	// 15 min tick: fine-grained enough for hourly (1h) without excessive DB load.
	tick time.Duration
}

// NewScheduler returns a Scheduler that checks for due feeds every tick interval.
func NewScheduler(feeds *Store, fetcher ManualFetcher, recorder CrawlRunRecorder, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		feeds:    feeds,
		fetcher:  fetcher,
		recorder: recorder,
		logger:   logger,
		tick:     15 * time.Minute,
	}
}

// Run blocks until ctx is cancelled, checking for due feeds on each tick.
// It runs an immediate check on start, then every tick interval.
func (s *Scheduler) Run(ctx context.Context) {
	s.logger.Info("feed scheduler started", "tick", s.tick)
	s.fetchDueFeeds(ctx)

	ticker := time.NewTicker(s.tick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("feed scheduler stopped")
			return
		case <-ticker.C:
			s.fetchDueFeeds(ctx)
		}
	}
}

// fetchDueFeeds iterates all schedule types and fetches feeds that are due.
func (s *Scheduler) fetchDueFeeds(ctx context.Context) {
	for _, sched := range scheduleOrder {
		if ctx.Err() != nil {
			return
		}
		if err := s.fetchSchedule(ctx, sched.name, sched.interval); err != nil {
			s.logger.Warn("schedule fetch failed", "schedule", sched.name, "error", err)
		}
	}
}

// fetchSchedule fetches all enabled feeds for a given schedule that are past their interval.
func (s *Scheduler) fetchSchedule(ctx context.Context, schedule string, interval time.Duration) error {
	feeds, err := s.feeds.EnabledFeedsBySchedule(ctx, schedule)
	if err != nil {
		return fmt.Errorf("listing feeds: %w", err)
	}

	now := time.Now()
	var fetched, skipped int

	for i := range feeds {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		f := &feeds[i]
		if f.LastFetchedAt != nil && now.Sub(*f.LastFetchedAt) < interval {
			skipped++
			continue
		}

		startedAt := time.Now()
		ids, fetchErr := s.fetcher.FetchFeed(ctx, f)
		s.recordFlowRun(ctx, f, ids, fetchErr, startedAt)

		if fetchErr != nil {
			s.logger.Warn("feed fetch failed",
				"feed", f.Name,
				"feed_id", f.ID,
				"error", fetchErr,
			)
			continue
		}

		fetched++
		if len(ids) > 0 {
			s.logger.Info("feed fetched",
				"feed", f.Name,
				"feed_id", f.ID,
				"new_items", len(ids),
			)
		}
	}

	if fetched > 0 || skipped < len(feeds) {
		s.logger.Info("schedule tick completed",
			"schedule", schedule,
			"total", len(feeds),
			"fetched", fetched,
			"skipped", skipped,
		)
	}

	return nil
}

func (s *Scheduler) recordFlowRun(ctx context.Context, f *Feed, ids []uuid.UUID, fetchErr error, startedAt time.Time) {
	input, _ := json.Marshal(map[string]string{ // best-effort: static map always serializable
		"feed_id":   f.ID.String(),
		"feed_name": f.Name,
		"schedule":  f.Schedule,
	})

	endedAt := time.Now()
	var status string
	var errMsg *string
	var output json.RawMessage

	if fetchErr != nil {
		status = "failed"
		msg := fetchErr.Error()
		errMsg = &msg
	} else {
		status = "completed"
		output, _ = json.Marshal(map[string]int{"new_items": len(ids)}) // best-effort: static map
	}

	if err := s.recorder.InsertCrawlRun(ctx, db.InsertCrawlRunParams{
		Name:      "feed_fetch",
		Input:     input,
		Output:    output,
		Status:    status,
		Error:     errMsg,
		StartedAt: &startedAt,
		EndedAt:   &endedAt,
	}); err != nil {
		s.logger.Warn("recording crawl run failed", "error", err) // best-effort
	}
}
