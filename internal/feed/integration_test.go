// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go covers the FK/CHECK → ErrInvalidInput classification on
// the feed write paths. A feed write whose url is not http(s)
// (chk_feed_url_scheme) or whose name is blank (chk_feed_name_not_blank) raises
// a check violation (23514) that must surface as feed.ErrInvalidInput — which
// the handler maps to HTTP 400 — instead of a wrapped error that
// api.HandleError would render as an opaque 500. mapWriteError is shared by
// CreateFeed and UpdateFeed, so the table drives both paths.
//
// Run with:
//
//	go test -tags=integration ./internal/feed/...
package feed_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/feed"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.NewPool()
	testPool = pool

	// feeds writes fire an audit trigger that writes activity_events.actor
	// (FK on agents). Seed the builtin registry so the fallback 'system' actor
	// is present.
	registry := agent.NewBuiltinRegistry()
	if _, err := agent.SyncToTable(context.Background(), registry, agent.NewStore(pool), nil, slog.Default()); err != nil {
		slog.Default().Error("agent.SyncToTable", "error", err)
		cleanup()
		os.Exit(1)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}

func truncate(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE feeds, feed_topics, activity_events CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// seedFeed inserts a valid feed row and returns its id, for the update-path
// cases that need an existing row to mutate.
func seedFeed(t *testing.T, url, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO feeds (url, name, schedule)
		 VALUES ($1, $2, 'daily') RETURNING id`,
		url, name,
	).Scan(&id); err != nil {
		t.Fatalf("seeding feed %q: %v", url, err)
	}
	return id
}

// TestIntegration_Feed_InvalidInput verifies the check-violation (23514) →
// ErrInvalidInput classification on both CreateFeed and UpdateFeed.
func TestIntegration_Feed_InvalidInput(t *testing.T) {
	truncate(t)
	store := feed.NewStore(testPool, slog.Default())
	ctx := t.Context()

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create with non-http url (chk_feed_url_scheme 23514)",
			run: func() error {
				_, err := store.CreateFeed(ctx, &feed.CreateParams{
					URL:      "ftp://example.com/feed.xml",
					Name:     "Bad scheme",
					Schedule: feed.ScheduleDaily,
				})
				return err
			},
		},
		{
			name: "create with blank name (chk_feed_name_not_blank 23514)",
			run: func() error {
				_, err := store.CreateFeed(ctx, &feed.CreateParams{
					URL:      "https://example.com/blank-name.xml",
					Name:     "   ",
					Schedule: feed.ScheduleDaily,
				})
				return err
			},
		},
		{
			name: "update to non-http url (chk_feed_url_scheme 23514)",
			run: func() error {
				id := seedFeed(t, "https://example.com/update-url.xml", "Update url target")
				badURL := "javascript:alert(1)"
				_, err := store.UpdateFeed(ctx, id, &feed.UpdateParams{URL: &badURL})
				return err
			},
		},
		{
			name: "update to blank name (chk_feed_name_not_blank 23514)",
			run: func() error {
				id := seedFeed(t, "https://example.com/update-name.xml", "Update name target")
				blank := "   "
				_, err := store.UpdateFeed(ctx, id, &feed.UpdateParams{Name: &blank})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, feed.ErrInvalidInput) {
				t.Fatalf("err = %v, want feed.ErrInvalidInput", err)
			}
		})
	}
}
