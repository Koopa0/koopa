// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// Integration coverage for the topic store's error-mapping contract:
// PostgreSQL check-constraint violations (23514) must surface as
// topic.ErrInvalidInput so the handler maps them to HTTP 400.
//
// Run with:
//
//	go test -tags=integration ./internal/topic/...
package topic_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/testdb"
	"github.com/Koopa0/koopa/internal/topic"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// contents insert fires an audit trigger that writes to
	// activity_events.actor (FK on agents). Seed the builtin registry so
	// the fallback 'system' actor is present.
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

// TestIntegration_Topic_InvalidInput verifies the check-violation (23514) →
// ErrInvalidInput classification on both CreateTopic and UpdateTopic: a
// malformed slug (chk_topic_slug_format) or a blank name
// (chk_topic_name_not_blank) must surface as topic.ErrInvalidInput, which the
// handler maps to HTTP 400, instead of a wrapped error rendered as 500.
func TestIntegration_Topic_InvalidInput(t *testing.T) {
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE topics CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	store := topic.NewStore(testPool)
	ctx := t.Context()

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create with malformed slug (chk_topic_slug_format 23514)",
			run: func() error {
				_, err := store.CreateTopic(ctx, &topic.CreateParams{
					Slug: "Not A Valid Slug!",
					Name: "Valid Name",
				})
				return err
			},
		},
		{
			name: "create with blank name (chk_topic_name_not_blank 23514)",
			run: func() error {
				_, err := store.CreateTopic(ctx, &topic.CreateParams{
					Slug: "valid-slug",
					Name: "   ",
				})
				return err
			},
		},
		{
			name: "update to malformed slug (chk_topic_slug_format 23514)",
			run: func() error {
				existing, err := store.CreateTopic(ctx, &topic.CreateParams{
					Slug: "update-target-slug",
					Name: "Update Target",
				})
				if err != nil {
					t.Fatalf("seeding topic for update: %v", err)
				}
				badSlug := "Bad Slug!!"
				_, err = store.UpdateTopic(ctx, existing.ID, &topic.UpdateParams{Slug: &badSlug})
				return err
			},
		},
		{
			name: "update to blank name (chk_topic_name_not_blank 23514)",
			run: func() error {
				existing, err := store.CreateTopic(ctx, &topic.CreateParams{
					Slug: "update-target-name",
					Name: "Update Target Name",
				})
				if err != nil {
					t.Fatalf("seeding topic for update: %v", err)
				}
				blank := "   "
				_, err = store.UpdateTopic(ctx, existing.ID, &topic.UpdateParams{Name: &blank})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, topic.ErrInvalidInput) {
				t.Fatalf("err = %v, want topic.ErrInvalidInput", err)
			}
		})
	}
}
