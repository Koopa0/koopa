package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// scheduleOrder defines a deterministic iteration order for feed schedules.
var scheduleOrder = []struct {
	name     string
	interval time.Duration
}{
	{ScheduleHourly4, 4 * time.Hour},
	{ScheduleDaily, 24 * time.Hour},
	{ScheduleWeekly, 7 * 24 * time.Hour},
}

// FlowRunRecorder writes flow run audit records.
type FlowRunRecorder interface {
	InsertFlowRun(ctx context.Context, arg db.InsertFlowRunParams) error
}

// Scheduler runs periodic feed fetches based on each feed's schedule.
type Scheduler struct {
	feeds    *Store
	fetcher  ManualFetcher
	recorder FlowRunRecorder
	logger   *slog.Logger
	// 15 min tick: fine-grained enough for hourly_4 (4h) without excessive DB load.
	tick time.Duration
}

// NewScheduler returns a Scheduler that checks for due feeds every tick interval.
func NewScheduler(feeds *Store, fetcher ManualFetcher, recorder FlowRunRecorder, logger *slog.Logger) *Scheduler {
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
	var status db.FlowStatus
	var errMsg *string
	var output json.RawMessage

	if fetchErr != nil {
		status = db.FlowStatusFailed
		msg := fetchErr.Error()
		errMsg = &msg
	} else {
		status = db.FlowStatusCompleted
		output, _ = json.Marshal(map[string]int{"new_items": len(ids)}) // best-effort: static map
	}

	if err := s.recorder.InsertFlowRun(ctx, db.InsertFlowRunParams{
		FlowName:  "feed_fetch",
		Input:     input,
		Output:    output,
		Status:    status,
		Error:     errMsg,
		StartedAt: &startedAt,
		EndedAt:   &endedAt,
	}); err != nil {
		s.logger.Warn("recording flow run failed", "error", err) // best-effort
	}
}
