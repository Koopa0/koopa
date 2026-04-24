package main

import (
	"context"
	"time"

	"github.com/Koopa0/koopa/internal/stats"
)

// statsFeedHealth adapts stats.Store.FeedHealth to the systemhealth
// FeedHealthReader interface.
type statsFeedHealth struct{ store *stats.Store }

func (a statsFeedHealth) FeedHealth(ctx context.Context) (enabled, failing int, err error) {
	fh, err := a.store.FeedHealth(ctx)
	if err != nil {
		return 0, 0, err
	}
	return fh.Enabled, fh.FailingFeeds, nil
}

// statsProcessRunSuccess adapts stats.Store.ProcessRunsSince to the
// systemhealth ProcessRunSuccessReader interface, projecting the 24h
// completed / total ratio into a percent.
type statsProcessRunSuccess struct{ store *stats.Store }

func (a statsProcessRunSuccess) SuccessRate24h(ctx context.Context, now time.Time) (pct float64, hasTraffic bool, err error) {
	pr, err := a.store.ProcessRunsSince(ctx, now.Add(-24*time.Hour), "crawl", nil, nil)
	if err != nil {
		return 0, false, err
	}
	if pr.Total == 0 {
		return 0, false, nil
	}
	return float64(pr.Completed) * 100.0 / float64(pr.Total), true, nil
}

// statsContentCount adapts stats.Store.Overview into a narrow contents-
// count source. When content.Store grows a dedicated TotalCount method
// this adapter can be swapped without touching systemhealth.
type statsContentCount struct{ store *stats.Store }

func (a statsContentCount) ContentsCount(ctx context.Context) (int, error) {
	ov, err := a.store.Overview(ctx)
	if err != nil {
		return 0, err
	}
	return ov.Contents.Total, nil
}
