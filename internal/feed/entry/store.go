// Copyright 2026 Koopa. All rights reserved.

package entry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

// nullCollectedStatus converts a *string to db.NullFeedEntryStatus.
func nullCollectedStatus(s *string) db.NullFeedEntryStatus {
	if s == nil {
		return db.NullFeedEntryStatus{}
	}
	return db.NullFeedEntryStatus{FeedEntryStatus: db.FeedEntryStatus(*s), Valid: true}
}

// Store handles database operations for collected data.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by callers
// composing multi-store transactions — typically via api.ActorMiddleware
// (HTTP) or mcp.Server.withActorTx (MCP). The tx carries koopa.actor
// so audit triggers attribute mutations correctly (feed_entries
// mutations curate and ignore are audited).
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// Items returns a paginated list of collected items.
func (s *Store) Items(ctx context.Context, f Filter) ([]Item, int, error) {
	status := nullCollectedStatus(f.Status)
	limit := int32(f.PerPage)                 // #nosec G115 -- pagination values are bounded by API layer
	offset := int32((f.Page - 1) * f.PerPage) // #nosec G115 -- pagination values are bounded by API layer

	rows, err := s.q.FeedEntriesList(ctx, db.FeedEntriesListParams{
		Limit:  limit,
		Offset: offset,
		Status: status,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing collected data: %w", err)
	}
	count, err := s.q.FeedEntriesCount(ctx, status)
	if err != nil {
		return nil, 0, fmt.Errorf("counting collected data: %w", err)
	}
	data := make([]Item, len(rows))
	for i := range rows {
		r := &rows[i]
		data[i] = rowToItem(collectedRow{
			ID: r.ID, SourceUrl: r.SourceUrl, Title: r.Title, OriginalContent: r.OriginalContent,
			Status:           r.Status,
			CuratedContentID: r.CuratedContentID, CollectedAt: r.CollectedAt, UrlHash: r.UrlHash,
			FeedID:      r.FeedID,
			PublishedAt: r.PublishedAt, FeedName: r.FeedName,
		})
	}
	return data, int(count), nil
}

// Curate marks collected data as curated and links to content.
// trg_feed_entries_curation_exclusion will reject the UPDATE if the same
// feed_entry is already referenced by bookmarks.source_feed_entry_id —
// that surfaces as PostgreSQL P0001 and is mapped to ErrConflict without
// propagating the trigger message (which contains the feed_entry UUID).
func (s *Store) Curate(ctx context.Context, id, contentID uuid.UUID) error {
	_, err := s.q.CurateFeedEntry(ctx, db.CurateFeedEntryParams{
		ID:               id,
		CuratedContentID: &contentID,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.RaiseException {
			return ErrConflict
		}
		return fmt.Errorf("curating collected data %s: %w", id, err)
	}
	return nil
}

// Ignore marks collected data as ignored.
func (s *Store) Ignore(ctx context.Context, id uuid.UUID) error {
	err := s.q.IgnoreFeedEntry(ctx, id)
	if err != nil {
		return fmt.Errorf("ignoring collected data %s: %w", id, err)
	}
	return nil
}

// CreateNewItems batch-inserts candidate items for one feed in a single
// round trip, deduplicating against existing rows via ON CONFLICT (url_hash)
// DO NOTHING. Returns only the ids that were actually inserted — conflicted
// (already-collected) items are silently absent from the result, not
// errored — so the caller does not need a separate pre-check per item.
// feedID applies to every item; empty items is a no-op (nil, nil).
func (s *Store) CreateNewItems(ctx context.Context, feedID *uuid.UUID, items []NewItem) ([]uuid.UUID, error) {
	if len(items) == 0 {
		return nil, nil
	}
	sourceURLs := make([]string, len(items))
	titles := make([]string, len(items))
	originalContents := make([]string, len(items))
	urlHashes := make([]string, len(items))
	publishedAts := make([]time.Time, len(items))
	hasPublished := make([]bool, len(items))
	for i := range items {
		sourceURLs[i] = items[i].SourceURL
		titles[i] = items[i].Title
		originalContents[i] = items[i].OriginalContent
		urlHashes[i] = items[i].URLHash
		if items[i].PublishedAt != nil {
			publishedAts[i] = *items[i].PublishedAt
			hasPublished[i] = true
		}
	}
	ids, err := s.q.CreateFeedEntries(ctx, db.CreateFeedEntriesParams{
		FeedID:           feedID,
		SourceUrls:       sourceURLs,
		Titles:           titles,
		OriginalContents: originalContents,
		UrlHashes:        urlHashes,
		PublishedAts:     publishedAts,
		HasPublished:     hasPublished,
	})
	if err != nil {
		return nil, fmt.Errorf("batch creating collected data: %w", err)
	}
	return ids, nil
}

// HighPriorityRecent returns unread items from high-priority feeds since the given time.
func (s *Store) HighPriorityRecent(ctx context.Context, since time.Time, maxResults int32) ([]Item, error) {
	rows, err := s.q.HighPriorityRecentFeedEntries(ctx, db.HighPriorityRecentFeedEntriesParams{
		Since:      since,
		MaxResults: maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("listing high priority collected data: %w", err)
	}
	data := make([]Item, len(rows))
	for i := range rows {
		r := &rows[i]
		data[i] = rowToItem(collectedRow{
			ID: r.ID, SourceUrl: r.SourceUrl, Title: r.Title, OriginalContent: r.OriginalContent,
			Status:           r.Status,
			CuratedContentID: r.CuratedContentID, CollectedAt: r.CollectedAt, UrlHash: r.UrlHash,
			FeedID:      r.FeedID,
			PublishedAt: r.PublishedAt, FeedName: r.FeedName,
		})
	}
	return data, nil
}

// collectedRow is the common field set shared by all sqlc-generated collected data
// row types. Each query returns a different Row type (CollectedDataRow, LatestFeedEntriesRow, etc.)
// but they all share the same fields including FeedName from the LEFT JOIN.
type collectedRow struct {
	ID               uuid.UUID
	SourceUrl        string //nolint:staticcheck,revive // matches sqlc-generated field name
	Title            string
	OriginalContent  string
	Status           db.FeedEntryStatus
	CuratedContentID *uuid.UUID
	CollectedAt      time.Time
	UrlHash          string //nolint:staticcheck,revive // matches sqlc-generated field name
	FeedID           *uuid.UUID
	PublishedAt      *time.Time
	FeedName         string
}

func rowToItem(r collectedRow) Item { //nolint:gocritic // hugeParam: struct passed by value matches codebase pattern
	return Item{
		ID:               r.ID,
		SourceURL:        r.SourceUrl,
		FeedName:         r.FeedName,
		Title:            r.Title,
		OriginalContent:  &r.OriginalContent,
		Status:           Status(r.Status),
		CuratedContentID: r.CuratedContentID,
		CollectedAt:      r.CollectedAt,
		PublishedAt:      r.PublishedAt,
		URLHash:          r.UrlHash,
		FeedID:           r.FeedID,
	}
}
