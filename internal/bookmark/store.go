package bookmark

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for bookmarks.
type Store struct {
	dbtx db.DBTX
	q    *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{dbtx: dbtx, q: db.New(dbtx)}
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

// Bookmarks returns a paginated list of public bookmarks.
func (s *Store) Bookmarks(ctx context.Context, f Filter) ([]Bookmark, int, error) {
	rows, err := s.q.PublicBookmarks(ctx, db.PublicBookmarksParams{
		Limit:  int32(f.PerPage),                // #nosec G115 -- pagination bounded in API layer
		Offset: int32((f.Page - 1) * f.PerPage), // #nosec G115 -- pagination bounded in API layer
		Since:  f.Since,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing bookmarks: %w", err)
	}

	total, err := s.q.PublicBookmarksCount(ctx, f.Since)
	if err != nil {
		return nil, 0, fmt.Errorf("counting bookmarks: %w", err)
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

// AdminBookmarks returns a paginated list for the admin surface. Admin
// listings include private bookmarks when IsPublic filter is nil.
func (s *Store) AdminBookmarks(ctx context.Context, f AdminFilter) ([]Bookmark, int, error) {
	rows, err := s.q.AdminBookmarks(ctx, db.AdminBookmarksParams{
		Limit:    int32(f.PerPage),                // #nosec G115 -- pagination bounded in API layer
		Offset:   int32((f.Page - 1) * f.PerPage), // #nosec G115 -- pagination bounded in API layer
		IsPublic: f.IsPublic,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("admin listing bookmarks: %w", err)
	}

	total, err := s.q.AdminBookmarksCount(ctx, f.IsPublic)
	if err != nil {
		return nil, 0, fmt.Errorf("counting admin bookmarks: %w", err)
	}

	out := make([]Bookmark, len(rows))
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		out[i] = bookmarkFromAdmin(&rows[i])
		ids[i] = rows[i].ID
	}
	if err := s.attachBatchTopicsAndTags(ctx, out, ids); err != nil {
		return nil, 0, err
	}
	return out, int(total), nil
}

// Create inserts a new bookmark. Returns ErrConflict when url_hash or slug
// collide with an existing row.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Bookmark, error) {
	r, err := s.q.CreateBookmark(ctx, db.CreateBookmarkParams{
		Url:               p.URL,
		UrlHash:           p.URLHash,
		Slug:              p.Slug,
		Title:             p.Title,
		Excerpt:           p.Excerpt,
		Note:              p.Note,
		SourceType:        string(p.SourceType),
		SourceFeedEntryID: p.FeedEntryID,
		CuratedBy:         p.CuratedBy,
		IsPublic:          p.IsPublic,
		PublishedAt:       p.PublishedAt,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating bookmark: %w", err)
	}

	for _, tid := range p.TopicIDs {
		if err := s.q.AddBookmarkTopic(ctx, db.AddBookmarkTopicParams{
			BookmarkID: r.ID,
			TopicID:    tid,
		}); err != nil {
			return nil, fmt.Errorf("attaching topic %s: %w", tid, err)
		}
	}

	b := bookmarkFromCreate(&r)
	if err := s.attachTopicsAndTags(ctx, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// Delete removes a bookmark. No-op on missing id; caller checks existence
// first if it needs to distinguish.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.q.DeleteBookmark(ctx, id); err != nil {
		return fmt.Errorf("deleting bookmark %s: %w", id, err)
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

// --- Row → Bookmark converters ---
//
// Each :one/:many query generates its own row type. The bookmark package
// presents a single domain type, so a small converter per row type keeps
// the rest of the store code straight.

func bookmarkFromByID(r *db.BookmarkByIDRow) Bookmark {
	return Bookmark{
		ID:                r.ID,
		URL:               r.Url,
		URLHash:           r.UrlHash,
		Slug:              r.Slug,
		Title:             r.Title,
		Excerpt:           r.Excerpt,
		Note:              r.Note,
		SourceType:        SourceType(r.SourceType),
		SourceFeedEntryID: r.SourceFeedEntryID,
		CuratedBy:         r.CuratedBy,
		CuratedAt:         r.CuratedAt,
		IsPublic:          r.IsPublic,
		PublishedAt:       r.PublishedAt,
		CreatedAt:         r.CreatedAt,
		UpdatedAt:         r.UpdatedAt,
	}
}

func bookmarkFromBySlug(r *db.BookmarkBySlugRow) Bookmark {
	return Bookmark{
		ID:                r.ID,
		URL:               r.Url,
		URLHash:           r.UrlHash,
		Slug:              r.Slug,
		Title:             r.Title,
		Excerpt:           r.Excerpt,
		Note:              r.Note,
		SourceType:        SourceType(r.SourceType),
		SourceFeedEntryID: r.SourceFeedEntryID,
		CuratedBy:         r.CuratedBy,
		CuratedAt:         r.CuratedAt,
		IsPublic:          r.IsPublic,
		PublishedAt:       r.PublishedAt,
		CreatedAt:         r.CreatedAt,
		UpdatedAt:         r.UpdatedAt,
	}
}

func bookmarkFromPublic(r *db.PublicBookmarksRow) Bookmark {
	return Bookmark{
		ID:                r.ID,
		URL:               r.Url,
		URLHash:           r.UrlHash,
		Slug:              r.Slug,
		Title:             r.Title,
		Excerpt:           r.Excerpt,
		Note:              r.Note,
		SourceType:        SourceType(r.SourceType),
		SourceFeedEntryID: r.SourceFeedEntryID,
		CuratedBy:         r.CuratedBy,
		CuratedAt:         r.CuratedAt,
		IsPublic:          r.IsPublic,
		PublishedAt:       r.PublishedAt,
		CreatedAt:         r.CreatedAt,
		UpdatedAt:         r.UpdatedAt,
	}
}

func bookmarkFromAdmin(r *db.AdminBookmarksRow) Bookmark {
	return Bookmark{
		ID:                r.ID,
		URL:               r.Url,
		URLHash:           r.UrlHash,
		Slug:              r.Slug,
		Title:             r.Title,
		Excerpt:           r.Excerpt,
		Note:              r.Note,
		SourceType:        SourceType(r.SourceType),
		SourceFeedEntryID: r.SourceFeedEntryID,
		CuratedBy:         r.CuratedBy,
		CuratedAt:         r.CuratedAt,
		IsPublic:          r.IsPublic,
		PublishedAt:       r.PublishedAt,
		CreatedAt:         r.CreatedAt,
		UpdatedAt:         r.UpdatedAt,
	}
}

func bookmarkFromCreate(r *db.CreateBookmarkRow) Bookmark {
	return Bookmark{
		ID:                r.ID,
		URL:               r.Url,
		URLHash:           r.UrlHash,
		Slug:              r.Slug,
		Title:             r.Title,
		Excerpt:           r.Excerpt,
		Note:              r.Note,
		SourceType:        SourceType(r.SourceType),
		SourceFeedEntryID: r.SourceFeedEntryID,
		CuratedBy:         r.CuratedBy,
		CuratedAt:         r.CuratedAt,
		IsPublic:          r.IsPublic,
		PublishedAt:       r.PublishedAt,
		CreatedAt:         r.CreatedAt,
		UpdatedAt:         r.UpdatedAt,
	}
}
