package bookmark

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

// Store handles database operations for bookmarks.
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
// so audit triggers attribute mutations correctly.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// Bookmark returns a single bookmark by ID, including its topics and tags.
func (s *Store) Bookmark(ctx context.Context, id uuid.UUID) (*Bookmark, error) {
	r, err := s.q.BookmarkByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying bookmark %s: %w", id, err)
	}

	b := bookmarkFromByID(&r)
	if err := s.attachTopicsAndTags(ctx, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// BookmarkBySlug returns a public bookmark by slug.
func (s *Store) BookmarkBySlug(ctx context.Context, slug string) (*Bookmark, error) {
	r, err := s.q.BookmarkBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying bookmark by slug %q: %w", slug, err)
	}

	b := bookmarkFromBySlug(&r)
	if err := s.attachTopicsAndTags(ctx, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// PublicBookmarks returns a paginated list filtered to is_public=true —
// the surface exposed at /api/bookmarks.
func (s *Store) PublicBookmarks(ctx context.Context, f PublicFilter) ([]Bookmark, int, error) {
	rows, err := s.q.PublicBookmarks(ctx, db.PublicBookmarksParams{
		Limit:  int32(f.PerPage),                // #nosec G115 -- pagination bounded in API layer
		Offset: int32((f.Page - 1) * f.PerPage), // #nosec G115 -- pagination bounded in API layer
		Since:  f.Since,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing public bookmarks: %w", err)
	}

	total, err := s.q.PublicBookmarksCount(ctx, f.Since)
	if err != nil {
		return nil, 0, fmt.Errorf("counting public bookmarks: %w", err)
	}

	out := make([]Bookmark, len(rows))
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		out[i] = bookmarkFromPublic(&rows[i])
		ids[i] = rows[i].ID
	}
	if err := s.attachBatchTopicsAndTags(ctx, out, ids); err != nil {
		return nil, 0, err
	}
	return out, int(total), nil
}

// Bookmarks returns a paginated list of every bookmark regardless of
// visibility. IsPublic on the Filter is an optional post-filter
// (nil = all). This is the surface the admin listing route uses.
func (s *Store) Bookmarks(ctx context.Context, f Filter) ([]Bookmark, int, error) {
	rows, err := s.q.ListBookmarks(ctx, db.ListBookmarksParams{
		Limit:    int32(f.PerPage),                // #nosec G115 -- pagination bounded in API layer
		Offset:   int32((f.Page - 1) * f.PerPage), // #nosec G115 -- pagination bounded in API layer
		IsPublic: f.IsPublic,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing bookmarks: %w", err)
	}

	total, err := s.q.CountBookmarks(ctx, f.IsPublic)
	if err != nil {
		return nil, 0, fmt.Errorf("counting bookmarks: %w", err)
	}

	out := make([]Bookmark, len(rows))
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		out[i] = bookmarkFromList(&rows[i])
		ids[i] = rows[i].ID
	}
	if err := s.attachBatchTopicsAndTags(ctx, out, ids); err != nil {
		return nil, 0, err
	}
	return out, int(total), nil
}

// Create inserts a new bookmark and attaches its topics.
//
// CALLER CONTRACT: this method performs multiple writes (the bookmark
// row plus one bookmark_topics row per TopicID). Callers that need
// atomicity MUST pass a tx-bound Store via WithTx(tx). Admin HTTP
// callers use ActorMiddleware which supplies the tx via request
// context; the bookmark handler routes through that path. Callers that
// invoke Create on a pool-backed Store get non-atomic writes — a
// failure during topic attach leaves the bookmark row behind.
//
// Returns ErrConflict when url_hash or slug collide with an existing
// row, or when trg_bookmarks_curation_exclusion fires (the referenced
// feed_entry is already curated as first-party content).
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Bookmark, error) {
	r, err := s.q.CreateBookmark(ctx, db.CreateBookmarkParams{
		Url:               p.URL,
		UrlHash:           p.URLHash,
		Slug:              p.Slug,
		Title:             p.Title,
		Excerpt:           p.Excerpt,
		Note:              p.Note,
		CaptureChannel:    string(p.CaptureChannel),
		SourceFeedEntryID: p.FeedEntryID,
		CuratedBy:         p.CuratedBy,
		IsPublic:          p.IsPublic,
		PublishedAt:       p.PublishedAt,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		if isCurationExclusionViolation(err) {
			// feed_entry already curated as first-party content — surface as
			// ErrConflict without leaking trigger details to callers.
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating bookmark: %w", err)
	}

	for _, tid := range p.TopicIDs {
		if topicErr := s.q.AddBookmarkTopic(ctx, db.AddBookmarkTopicParams{
			BookmarkID: r.ID,
			TopicID:    tid,
		}); topicErr != nil {
			return nil, fmt.Errorf("attaching topic %s: %w", tid, topicErr)
		}
	}

	b := bookmarkFromCreate(&r)
	if err := s.attachTopicsAndTags(ctx, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// Update applies partial scalar edits to a bookmark row and, when the
// corresponding pointer is non-nil, full-replaces its topic and tag
// attachments. Topic / tag replacement is sequenced as delete-then-add so
// an empty slice cleanly zeroes the junction. Callers MUST use a
// tx-bound Store (via WithTx) when they need the row update + junction
// rewrite to be atomic; the admin HTTP handler routes via ActorMiddleware
// which supplies the tx. Returns ErrNotFound when id does not resolve.
func (s *Store) Update(ctx context.Context, id uuid.UUID, p UpdateParams) (*Bookmark, error) {
	r, err := s.q.UpdateBookmark(ctx, db.UpdateBookmarkParams{
		ID:      id,
		Title:   p.Title,
		Excerpt: p.Excerpt,
		Note:    p.Note,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating bookmark %s: %w", id, err)
	}

	if p.TopicIDs != nil {
		if err := s.q.DeleteBookmarkTopics(ctx, id); err != nil {
			return nil, fmt.Errorf("clearing bookmark topics for %s: %w", id, err)
		}
		for _, tid := range *p.TopicIDs {
			if err := s.q.AddBookmarkTopic(ctx, db.AddBookmarkTopicParams{
				BookmarkID: id,
				TopicID:    tid,
			}); err != nil {
				return nil, fmt.Errorf("attaching topic %s to bookmark %s: %w", tid, id, err)
			}
		}
	}

	if p.TagIDs != nil {
		if err := s.q.DeleteBookmarkTags(ctx, id); err != nil {
			return nil, fmt.Errorf("clearing bookmark tags for %s: %w", id, err)
		}
		for _, tid := range *p.TagIDs {
			if err := s.q.AddBookmarkTag(ctx, db.AddBookmarkTagParams{
				BookmarkID: id,
				TagID:      tid,
			}); err != nil {
				return nil, fmt.Errorf("attaching tag %s to bookmark %s: %w", tid, id, err)
			}
		}
	}

	b := bookmarkFromUpdate(&r)
	if err := s.attachTopicsAndTags(ctx, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// Delete removes a bookmark. Returns ErrNotFound when no row with the
// given id exists; the HTTP DELETE contract relies on this to send 404
// rather than 204 for a missing target.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	rows, err := s.q.DeleteBookmark(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting bookmark %s: %w", id, err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// attachTopicsAndTags populates Topics and Tags on a single bookmark.
func (s *Store) attachTopicsAndTags(ctx context.Context, b *Bookmark) error {
	topicRows, err := s.q.TopicsForBookmark(ctx, b.ID)
	if err != nil {
		return fmt.Errorf("loading topics for bookmark %s: %w", b.ID, err)
	}
	b.Topics = make([]TopicRef, len(topicRows))
	for i, t := range topicRows {
		b.Topics[i] = TopicRef{ID: t.ID, Slug: t.Slug, Name: t.Name}
	}

	tagRows, err := s.q.TagsForBookmark(ctx, b.ID)
	if err != nil {
		return fmt.Errorf("loading tags for bookmark %s: %w", b.ID, err)
	}
	b.Tags = tagRows
	if b.Tags == nil {
		b.Tags = []string{}
	}
	return nil
}

// attachBatchTopicsAndTags populates Topics and Tags for a list of bookmarks
// with two batch queries instead of 2N round-trips.
func (s *Store) attachBatchTopicsAndTags(ctx context.Context, out []Bookmark, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	topicRows, err := s.q.TopicsForBookmarks(ctx, ids)
	if err != nil {
		return fmt.Errorf("batch loading bookmark topics: %w", err)
	}
	topicsByID := make(map[uuid.UUID][]TopicRef, len(ids))
	for _, t := range topicRows {
		topicsByID[t.BookmarkID] = append(topicsByID[t.BookmarkID], TopicRef{
			ID: t.ID, Slug: t.Slug, Name: t.Name,
		})
	}

	tagRows, err := s.q.TagsForBookmarks(ctx, ids)
	if err != nil {
		return fmt.Errorf("batch loading bookmark tags: %w", err)
	}
	tagsByID := make(map[uuid.UUID][]string, len(ids))
	for _, t := range tagRows {
		tagsByID[t.BookmarkID] = append(tagsByID[t.BookmarkID], t.Name)
	}

	for i := range out {
		id := out[i].ID
		if topics, ok := topicsByID[id]; ok {
			out[i].Topics = topics
		} else {
			out[i].Topics = []TopicRef{}
		}
		if tags, ok := tagsByID[id]; ok {
			out[i].Tags = tags
		} else {
			out[i].Tags = []string{}
		}
	}
	return nil
}

// isUniqueViolation reports whether err is a PostgreSQL unique_violation
// (23505). Used to map insert conflicts to ErrConflict.
func isUniqueViolation(err error) bool {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return pgErr.Code == pgerrcode.UniqueViolation
	}
	return false
}

// isCurationExclusionViolation reports whether err is a PL/pgSQL RAISE
// EXCEPTION (P0001) from trg_bookmarks_curation_exclusion — the referenced
// feed_entry already has a curated_content_id. Mapped to ErrConflict without
// propagating the trigger message (which contains the feed_entry UUID).
func isCurationExclusionViolation(err error) bool {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return pgErr.Code == pgerrcode.RaiseException
	}
	return false
}

// --- Row → Bookmark converters ---
//
// sqlc generates a distinct row type per query, so each converter is a
// one-line thunk that feeds its fields into a single assembleBookmark
// helper. Adding a field to Bookmark means touching one site — the
// assembler — plus the query.sql SELECT lists. The thunks remain
// trivially correct at a glance.

// assembleBookmark builds a Bookmark value from the flat field set that
// every sqlc row type carries. Keeping the per-row thunks thin avoids
// the drift risk of five hand-maintained converter bodies — adding a
// column touches this one helper plus the query.sql SELECT lists.
func assembleBookmark(
	id uuid.UUID,
	url, urlHash, slug, title, excerpt, note string,
	captureChannel string,
	sourceFeedEntryID *uuid.UUID,
	curatedBy string,
	curatedAt time.Time,
	isPublic bool,
	publishedAt time.Time,
	createdAt, updatedAt time.Time,
) Bookmark {
	return Bookmark{
		ID:                id,
		URL:               url,
		URLHash:           urlHash,
		Slug:              slug,
		Title:             title,
		Excerpt:           excerpt,
		Note:              note,
		CaptureChannel:    Channel(captureChannel),
		SourceFeedEntryID: sourceFeedEntryID,
		CuratedBy:         curatedBy,
		CuratedAt:         curatedAt,
		IsPublic:          isPublic,
		PublishedAt:       publishedAt,
		CreatedAt:         createdAt,
		UpdatedAt:         updatedAt,
	}
}

func bookmarkFromByID(r *db.BookmarkByIDRow) Bookmark {
	return assembleBookmark(
		r.ID, r.Url, r.UrlHash, r.Slug, r.Title, r.Excerpt, r.Note,
		r.CaptureChannel, r.SourceFeedEntryID, r.CuratedBy, r.CuratedAt,
		r.IsPublic, r.PublishedAt, r.CreatedAt, r.UpdatedAt,
	)
}

func bookmarkFromBySlug(r *db.BookmarkBySlugRow) Bookmark {
	return assembleBookmark(
		r.ID, r.Url, r.UrlHash, r.Slug, r.Title, r.Excerpt, r.Note,
		r.CaptureChannel, r.SourceFeedEntryID, r.CuratedBy, r.CuratedAt,
		r.IsPublic, r.PublishedAt, r.CreatedAt, r.UpdatedAt,
	)
}

func bookmarkFromPublic(r *db.PublicBookmarksRow) Bookmark {
	return assembleBookmark(
		r.ID, r.Url, r.UrlHash, r.Slug, r.Title, r.Excerpt, r.Note,
		r.CaptureChannel, r.SourceFeedEntryID, r.CuratedBy, r.CuratedAt,
		r.IsPublic, r.PublishedAt, r.CreatedAt, r.UpdatedAt,
	)
}

func bookmarkFromList(r *db.ListBookmarksRow) Bookmark {
	return assembleBookmark(
		r.ID, r.Url, r.UrlHash, r.Slug, r.Title, r.Excerpt, r.Note,
		r.CaptureChannel, r.SourceFeedEntryID, r.CuratedBy, r.CuratedAt,
		r.IsPublic, r.PublishedAt, r.CreatedAt, r.UpdatedAt,
	)
}

func bookmarkFromCreate(r *db.CreateBookmarkRow) Bookmark {
	return assembleBookmark(
		r.ID, r.Url, r.UrlHash, r.Slug, r.Title, r.Excerpt, r.Note,
		r.CaptureChannel, r.SourceFeedEntryID, r.CuratedBy, r.CuratedAt,
		r.IsPublic, r.PublishedAt, r.CreatedAt, r.UpdatedAt,
	)
}

func bookmarkFromUpdate(r *db.UpdateBookmarkRow) Bookmark {
	return assembleBookmark(
		r.ID, r.Url, r.UrlHash, r.Slug, r.Title, r.Excerpt, r.Note,
		r.CaptureChannel, r.SourceFeedEntryID, r.CuratedBy, r.CuratedAt,
		r.IsPublic, r.PublishedAt, r.CreatedAt, r.UpdatedAt,
	)
}
