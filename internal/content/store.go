package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pgvector/pgvector-go"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// nullSourceType converts a *SourceType to db.NullSourceType.
func nullSourceType(st *SourceType) db.NullSourceType {
	if st == nil {
		return db.NullSourceType{}
	}
	return db.NullSourceType{SourceType: db.SourceType(*st), Valid: true}
}

// nullSourceTypeToPtr converts db.NullSourceType to *SourceType.
func nullSourceTypeToPtr(st db.NullSourceType) *SourceType {
	if !st.Valid {
		return nil
	}
	v := SourceType(st.SourceType)
	return &v
}

// nullContentType converts a *Type to db.NullContentType.
func nullContentType(t *Type) db.NullContentType {
	if t == nil {
		return db.NullContentType{}
	}
	return db.NullContentType{ContentType: db.ContentType(*t), Valid: true}
}

// nullContentStatus converts a *Status to db.NullContentStatus.
func nullContentStatus(s *Status) db.NullContentStatus {
	if s == nil {
		return db.NullContentStatus{}
	}
	return db.NullContentStatus{ContentStatus: db.ContentStatus(*s), Valid: true}
}

// nullReviewLevel converts a *ReviewLevel to db.NullReviewLevel.
func nullReviewLevel(rl *ReviewLevel) db.NullReviewLevel {
	if rl == nil {
		return db.NullReviewLevel{}
	}
	return db.NullReviewLevel{ReviewLevel: db.ReviewLevel(*rl), Valid: true}
}

// Store handles database operations for content.
type Store struct {
	dbtx db.DBTX
	q    *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{dbtx: dbtx, q: db.New(dbtx)}
}

// Content returns a single content by ID.
func (s *Store) Content(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.ContentByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying content %s: %w", id, err)
	}

	c := rowToContent(contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})

	topics, err := s.TopicsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Topics = topics

	tags, err := s.TagsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Tags = tags

	return &c, nil
}

// Contents returns a paginated list of published contents.
func (s *Store) Contents(ctx context.Context, f Filter) ([]Content, int, error) {
	ct := nullContentType(f.Type)

	rows, err := s.q.PublishedContents(ctx, db.PublishedContentsParams{
		Limit:       int32(f.PerPage),                // #nosec G115 -- pagination values are bounded by API layer
		Offset:      int32((f.Page - 1) * f.PerPage), // #nosec G115 -- pagination values are bounded by API layer
		ContentType: ct,
		Since:       f.Since,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing contents: %w", err)
	}

	countRow, err := s.q.PublishedContentsCount(ctx, db.PublishedContentsCountParams{
		ContentType: ct,
		Since:       f.Since,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("counting contents: %w", err)
	}

	contents := make([]Content, len(rows))
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		r := rows[i]
		contents[i] = rowToContent(contentRow{
			ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
			Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
		ids[i] = r.ID
	}

	// batch fetch topics and tags for all contents in a single query
	topicMap, err := s.topicsForContents(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	tagMap, err := s.tagsForContents(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	for i := range contents {
		contents[i].Topics = topicMap[contents[i].ID]
		contents[i].Tags = tagMap[contents[i].ID]
	}

	return contents, int(countRow), nil
}

// AdminContents returns a paginated list of all contents for admin (no status/visibility filter).
func (s *Store) AdminContents(ctx context.Context, f AdminFilter) ([]Content, int, error) {
	ct := nullContentType(f.Type)

	rows, err := s.q.AdminListContents(ctx, db.AdminListContentsParams{
		Limit:       int32(f.PerPage),                // #nosec G115 -- pagination values are bounded by API layer
		Offset:      int32((f.Page - 1) * f.PerPage), // #nosec G115 -- pagination values are bounded by API layer
		ContentType: ct,
		IsPublic:    f.IsPublic,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("admin listing contents: %w", err)
	}

	countRow, err := s.q.AdminListContentsCount(ctx, db.AdminListContentsCountParams{
		ContentType: ct,
		IsPublic:    f.IsPublic,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("counting admin contents: %w", err)
	}

	contents := make([]Content, len(rows))
	for i := range rows {
		r := rows[i]
		contents[i] = Content{
			ID:             r.ID,
			Slug:           r.Slug,
			Title:          r.Title,
			Excerpt:        r.Excerpt,
			Type:           Type(r.Type),
			Status:         Status(r.Status),
			IsPublic:       r.IsPublic,
			ProjectID:      r.ProjectID,
			ReadingTimeMin: int(r.ReadingTimeMin),
			PublishedAt:    r.PublishedAt,
			CreatedAt:      r.CreatedAt,
			UpdatedAt:      r.UpdatedAt,
		}
	}

	return contents, int(countRow), nil
}

// ContentBySlug returns a single content by slug.
func (s *Store) ContentBySlug(ctx context.Context, slug string) (*Content, error) {
	r, err := s.q.ContentBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying content %s: %w", slug, err)
	}

	c := rowToContent(contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})

	topics, err := s.TopicsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Topics = topics

	tags, err := s.TagsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Tags = tags

	return &c, nil
}

// ContentsByTopicID returns published contents for a topic.
func (s *Store) ContentsByTopicID(ctx context.Context, topicID uuid.UUID, page, perPage int) ([]Content, int, error) {
	rows, err := s.q.ContentsByTopicID(ctx, db.ContentsByTopicIDParams{
		TopicID: topicID,
		Limit:   int32(perPage),              // #nosec G115 -- pagination values are bounded by API layer
		Offset:  int32((page - 1) * perPage), // #nosec G115 -- pagination values are bounded by API layer
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing contents by topic: %w", err)
	}

	count, err := s.q.ContentsByTopicIDCount(ctx, topicID)
	if err != nil {
		return nil, 0, fmt.Errorf("counting contents by topic: %w", err)
	}

	contents := make([]Content, len(rows))
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		r := rows[i]
		contents[i] = rowToContent(contentRow{
			ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
			Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
		ids[i] = r.ID
	}

	tagMap, err := s.tagsForContents(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	for i := range contents {
		contents[i].Tags = tagMap[contents[i].ID]
	}

	return contents, int(count), nil
}

// Search performs full-text search on published content.
func (s *Store) Search(ctx context.Context, query string, contentType *Type, page, perPage int) ([]Content, int, error) {
	ct := nullContentType(contentType)

	rows, err := s.q.SearchContents(ctx, db.SearchContentsParams{
		WebsearchToTsquery: query,
		Limit:              int32(perPage),              // #nosec G115 -- pagination values are bounded by API layer
		Offset:             int32((page - 1) * perPage), // #nosec G115 -- pagination values are bounded by API layer
		ContentType:        ct,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("searching contents: %w", err)
	}

	count, err := s.q.SearchContentsCount(ctx, db.SearchContentsCountParams{
		WebsearchToTsquery: query,
		ContentType:        ct,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("counting search results: %w", err)
	}

	contents := make([]Content, len(rows))
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		r := &rows[i]
		contents[i] = rowToContent(contentRow{
			ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
			Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
		ids[i] = r.ID
	}

	tagMap, err := s.tagsForContents(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	for i := range contents {
		contents[i].Tags = tagMap[contents[i].ID]
	}

	return contents, int(count), nil
}

// SearchOR performs full-text search using OR semantics (any word matches).
func (s *Store) SearchOR(ctx context.Context, query string, contentType *Type, page, perPage int) ([]Content, int, error) {
	ct := nullContentType(contentType)
	rows, err := s.q.SearchContentsOR(ctx, db.SearchContentsORParams{
		PlaintoTsquery: query,
		Limit:          int32(perPage),              // #nosec G115 -- pagination values are bounded by API layer
		Offset:         int32((page - 1) * perPage), // #nosec G115 -- pagination values are bounded by API layer
		ContentType:    ct,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("searching contents (OR): %w", err)
	}

	count, err := s.q.SearchContentsORCount(ctx, db.SearchContentsORCountParams{
		PlaintoTsquery: query,
		ContentType:    ct,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("counting search OR results: %w", err)
	}

	contents := make([]Content, len(rows))
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		r := &rows[i]
		contents[i] = rowToContent(contentRow{
			ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
			Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
		ids[i] = r.ID
	}

	tagMap, err := s.tagsForContents(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	for i := range contents {
		contents[i].Tags = tagMap[contents[i].ID]
	}

	return contents, int(count), nil
}

// InternalSearch performs full-text search on published content without visibility filter.
// Used by MCP tools that need access to all content including private.
func (s *Store) InternalSearch(ctx context.Context, query string, page, perPage int) ([]Content, int, error) {
	rows, err := s.q.InternalSearchContents(ctx, db.InternalSearchContentsParams{
		WebsearchToTsquery: query,
		Limit:              int32(perPage),              // #nosec G115 -- pagination values are bounded by API layer
		Offset:             int32((page - 1) * perPage), // #nosec G115 -- pagination values are bounded by API layer
	})
	if err != nil {
		return nil, 0, fmt.Errorf("internal searching contents: %w", err)
	}

	count, err := s.q.InternalSearchContentsCount(ctx, query)
	if err != nil {
		return nil, 0, fmt.Errorf("counting internal search results: %w", err)
	}

	contents := make([]Content, len(rows))
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		r := &rows[i]
		contents[i] = rowToContent(contentRow{
			ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
			Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
		ids[i] = r.ID
	}

	tagMap, err := s.tagsForContents(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	for i := range contents {
		contents[i].Tags = tagMap[contents[i].ID]
	}

	return contents, int(count), nil
}

// InternalSearchOR performs full-text search using OR semantics without visibility filter.
// Used by MCP tools that need access to all content including private.
func (s *Store) InternalSearchOR(ctx context.Context, query string, page, perPage int) ([]Content, int, error) {
	rows, err := s.q.InternalSearchContentsOR(ctx, db.InternalSearchContentsORParams{
		PlaintoTsquery: query,
		Limit:          int32(perPage),              // #nosec G115 -- pagination values are bounded by API layer
		Offset:         int32((page - 1) * perPage), // #nosec G115 -- pagination values are bounded by API layer
	})
	if err != nil {
		return nil, 0, fmt.Errorf("internal searching contents (OR): %w", err)
	}

	contents := make([]Content, len(rows))
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		r := &rows[i]
		contents[i] = rowToContent(contentRow{
			ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
			Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
		ids[i] = r.ID
	}

	tagMap, err := s.tagsForContents(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	for i := range contents {
		contents[i].Tags = tagMap[contents[i].ID]
	}

	return contents, len(contents), nil
}

// RecentByType returns recent contents of a specific type since a given time.
func (s *Store) RecentByType(ctx context.Context, contentType Type, since time.Time, limit int) ([]Content, error) {
	rows, err := s.q.RecentContentsByType(ctx, db.RecentContentsByTypeParams{
		ContentType: db.ContentType(contentType),
		Since:       since,
		MaxResults:  int32(limit), // #nosec G115 -- limit is bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("listing recent %s: %w", contentType, err)
	}
	contents := make([]Content, len(rows))
	for i := range rows {
		r := &rows[i]
		contents[i] = rowToContent(contentRow{
			ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
			Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
	}
	return contents, nil
}

// AddContentTag inserts a tag association for a content record.
func (s *Store) AddContentTag(ctx context.Context, contentID, tagID uuid.UUID) error {
	return s.q.AddContentTag(ctx, db.AddContentTagParams{
		ContentID: contentID,
		TagID:     tagID,
	})
}

// TagEntry is a lightweight record for learning analytics aggregation.
type TagEntry struct {
	ID        uuid.UUID
	Tags      []string
	CreatedAt time.Time
}

// TagEntries returns id, tags, and created_at for contents of a given type,
// optionally filtered by project. Used for learning analytics aggregation.
// Tags are loaded from the content_tags junction table via batch query.
func (s *Store) TagEntries(ctx context.Context, contentType Type, projectID *uuid.UUID, since time.Time) ([]TagEntry, error) {
	rows, err := s.q.ContentRichTagEntries(ctx, db.ContentRichTagEntriesParams{
		ContentType: db.ContentType(contentType),
		ProjectID:   projectID,
		Since:       since,
	})
	if err != nil {
		return nil, fmt.Errorf("querying tag entries: %w", err)
	}
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		ids[i] = rows[i].ID
	}
	tagMap, err := s.tagsForContents(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("batch loading tags for tag entries: %w", err)
	}
	entries := make([]TagEntry, len(rows))
	for i := range rows {
		entries[i] = TagEntry{
			ID:        rows[i].ID,
			Tags:      tagMap[rows[i].ID],
			CreatedAt: rows[i].CreatedAt,
		}
	}
	return entries, nil
}

// RichTagEntry is a content record with slug, title, ai_metadata, and project
// for learning analytics that need structured metadata (weakness trend, timeline).
// Heavier than TagEntry — only use when slug/title/metadata are needed.
type RichTagEntry struct {
	ID          uuid.UUID
	Slug        string
	Title       string
	Tags        []string
	AIMetadata  json.RawMessage // nil when content has no structured metadata
	ProjectSlug string          // empty when content has no project
	CreatedAt   time.Time
}

// RichTagEntries returns entries with slug, title, and ai_metadata for a given
// content type, optionally filtered by project. Used by weakness_trend and
// learning_timeline which need per-entry metadata.
func (s *Store) RichTagEntries(ctx context.Context, contentType Type, projectID *uuid.UUID, since time.Time) ([]RichTagEntry, error) {
	rows, err := s.q.ContentRichTagEntries(ctx, db.ContentRichTagEntriesParams{
		ContentType: db.ContentType(contentType),
		ProjectID:   projectID,
		Since:       since,
	})
	if err != nil {
		return nil, fmt.Errorf("querying rich tag entries: %w", err)
	}
	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		ids[i] = rows[i].ID
	}
	tagMap, err := s.tagsForContents(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("batch loading tags for rich tag entries: %w", err)
	}
	entries := make([]RichTagEntry, len(rows))
	for i := range rows {
		var projectSlug string
		if rows[i].ProjectSlug != nil {
			projectSlug = *rows[i].ProjectSlug
		}
		entries[i] = RichTagEntry{
			ID:          rows[i].ID,
			Slug:        rows[i].Slug,
			Title:       rows[i].Title,
			Tags:        tagMap[rows[i].ID],
			AIMetadata:  rows[i].AiMetadata,
			ProjectSlug: projectSlug,
			CreatedAt:   rows[i].CreatedAt,
		}
	}
	return entries, nil
}

// PublishedForRSS returns recent published content for RSS feed.
func (s *Store) PublishedForRSS(ctx context.Context, limit int) ([]Content, error) {
	rows, err := s.q.PublishedForRSS(ctx, int32(limit)) // #nosec G115 -- RSS limit is a small constant, not user-controlled
	if err != nil {
		return nil, fmt.Errorf("listing contents for rss: %w", err)
	}
	contents := make([]Content, len(rows))
	for i, r := range rows {
		contents[i] = Content{
			ID:          r.ID,
			Slug:        r.Slug,
			Title:       r.Title,
			Excerpt:     r.Excerpt,
			Type:        Type(r.Type),
			PublishedAt: r.PublishedAt,
			UpdatedAt:   r.UpdatedAt,
		}
	}
	return contents, nil
}

// PublishedByDateRange returns published content within a time range.
func (s *Store) PublishedByDateRange(ctx context.Context, start, end time.Time) ([]Content, error) {
	rows, err := s.q.PublishedContentsByDateRange(ctx, db.PublishedContentsByDateRangeParams{
		PublishedAt:   &start,
		PublishedAt_2: &end,
	})
	if err != nil {
		return nil, fmt.Errorf("listing published contents by date range: %w", err)
	}
	contents := make([]Content, len(rows))
	for i := range rows {
		r := &rows[i]
		contents[i] = rowToContent(contentRow{
			ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
			Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
	}
	return contents, nil
}

// PublishedContentCountSince returns the number of published articles since the given time.
func (s *Store) PublishedContentCountSince(ctx context.Context, since time.Time) (int64, error) {
	count, err := s.q.PublishedContentCountSince(ctx, &since)
	if err != nil {
		return 0, fmt.Errorf("counting published contents since %s: %w", since.Format("2006-01-02"), err)
	}
	return count, nil
}

// AllPublishedSlugs returns all published content slugs for sitemap.
func (s *Store) AllPublishedSlugs(ctx context.Context) ([]Content, error) {
	rows, err := s.q.AllPublishedSlugs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing slugs for sitemap: %w", err)
	}
	contents := make([]Content, len(rows))
	for i, r := range rows {
		contents[i] = Content{
			Slug:      r.Slug,
			Type:      Type(r.Type),
			UpdatedAt: r.UpdatedAt,
		}
	}
	return contents, nil
}

// ObsidianContentSlugs returns all slugs for content sourced from Obsidian.
func (s *Store) ObsidianContentSlugs(ctx context.Context) ([]string, error) {
	return s.q.ObsidianContentSlugs(ctx)
}

// CreateContent inserts a new content and associates topics and tags within a transaction.
func (s *Store) CreateContent(ctx context.Context, p *CreateParams) (*Content, error) {
	var seriesOrder *int32
	if p.SeriesOrder != nil {
		v := int32(*p.SeriesOrder) // #nosec G115 -- series order is a small sequential value, not user-controlled
		seriesOrder = &v
	}

	// Transaction exception: CreateContent starts its own tx because it must
	// atomically insert content + sync topic/tag junctions. Moving the tx boundary
	// to every handler/caller would increase coupling with no safety gain —
	// content creation is always a single logical operation.
	pool, ok := s.dbtx.(interface {
		Begin(ctx context.Context) (pgx.Tx, error)
	})
	if !ok {
		return nil, fmt.Errorf("create content requires a connection with begin support")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is no-op after commit

	qtx := s.q.WithTx(tx)

	r, err := qtx.CreateContent(ctx, db.CreateContentParams{
		Slug:           p.Slug,
		Title:          p.Title,
		Body:           p.Body,
		Excerpt:        p.Excerpt,
		Type:           db.ContentType(p.Type),
		Status:         db.ContentStatus(p.Status),
		Source:         p.Source,
		SourceType:     nullSourceType(p.SourceType),
		SeriesID:       p.SeriesID,
		SeriesOrder:    seriesOrder,
		ReviewLevel:    db.ReviewLevel(p.ReviewLevel),
		IsPublic:       p.IsPublic,
		ProjectID:      p.ProjectID,
		AiMetadata:     p.AIMetadata,
		ReadingTimeMin: int32(p.ReadingTimeMin), // #nosec G115 -- reading time in minutes is bounded, not user-controlled
		CoverImage:     p.CoverImage,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating content: %w", err)
	}

	for _, topicID := range p.TopicIDs {
		if topicErr := qtx.AddContentTopic(ctx, db.AddContentTopicParams{
			ContentID: r.ID,
			TopicID:   topicID,
		}); topicErr != nil {
			return nil, fmt.Errorf("adding content topic: %w", topicErr)
		}
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return nil, fmt.Errorf("committing transaction: %w", commitErr)
	}

	c := rowToContent(contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})

	// Topic and tag fetch is outside the transaction — content is already committed.
	// On failure, return the content with empty collections rather than failing
	// the entire operation (the content write succeeded).
	topics, err := s.TopicsForContent(ctx, c.ID)
	if err != nil {
		c.Topics = []TopicRef{}
		return &c, nil
	}
	c.Topics = topics

	tags, err := s.TagsForContent(ctx, c.ID)
	if err != nil {
		c.Tags = []string{}
		return &c, nil
	}
	c.Tags = tags

	return &c, nil
}

// UpdateContent updates a content and replaces topic associations within a transaction.
func (s *Store) UpdateContent(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Content, error) {
	var readingTimeMin *int32
	if p.ReadingTimeMin != nil {
		v := int32(*p.ReadingTimeMin) // #nosec G115 -- reading time in minutes is bounded, not user-controlled
		readingTimeMin = &v
	}
	var seriesOrder *int32
	if p.SeriesOrder != nil {
		v := int32(*p.SeriesOrder) // #nosec G115 -- series order is a small sequential value, not user-controlled
		seriesOrder = &v
	}

	// Transaction exception: same rationale as CreateContent (see above).
	pool, ok := s.dbtx.(interface {
		Begin(ctx context.Context) (pgx.Tx, error)
	})
	if !ok {
		return nil, fmt.Errorf("update content requires a connection with begin support")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is no-op after commit

	qtx := s.q.WithTx(tx)

	r, err := qtx.UpdateContent(ctx, db.UpdateContentParams{
		ID:             id,
		Slug:           p.Slug,
		Title:          p.Title,
		Body:           p.Body,
		Excerpt:        p.Excerpt,
		ContentType:    nullContentType(p.Type),
		Status:         nullContentStatus(p.Status),
		Source:         p.Source,
		SourceType:     nullSourceType(p.SourceType),
		SeriesID:       p.SeriesID,
		SeriesOrder:    seriesOrder,
		ReviewLevel:    nullReviewLevel(p.ReviewLevel),
		IsPublic:       p.IsPublic,
		ProjectID:      p.ProjectID,
		AiMetadata:     p.AIMetadata,
		ReadingTimeMin: readingTimeMin,
		CoverImage:     p.CoverImage,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("updating content %s: %w", id, err)
	}

	if p.TopicIDs != nil {
		if deleteErr := qtx.DeleteContentTopics(ctx, id); deleteErr != nil {
			return nil, fmt.Errorf("clearing content topics: %w", deleteErr)
		}
		for _, topicID := range p.TopicIDs {
			if topicErr := qtx.AddContentTopic(ctx, db.AddContentTopicParams{
				ContentID: id,
				TopicID:   topicID,
			}); topicErr != nil {
				return nil, fmt.Errorf("adding content topic: %w", topicErr)
			}
		}
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return nil, fmt.Errorf("committing transaction: %w", commitErr)
	}

	c := rowToContent(contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})

	// Topic and tag fetch is outside the transaction — update is already committed.
	// On failure, return the content with empty collections rather than failing.
	topics, err := s.TopicsForContent(ctx, c.ID)
	if err != nil {
		c.Topics = []TopicRef{}
		return &c, nil
	}
	c.Topics = topics

	tags, err := s.TagsForContent(ctx, c.ID)
	if err != nil {
		c.Tags = []string{}
		return &c, nil
	}
	c.Tags = tags

	return &c, nil
}

// UpdateEmbedding writes the embedding vector for a content item.
func (s *Store) UpdateEmbedding(ctx context.Context, id uuid.UUID, embedding pgvector.Vector) error {
	err := s.q.UpdateContentEmbedding(ctx, db.UpdateContentEmbeddingParams{
		ID:        id,
		Embedding: &embedding,
	})
	if err != nil {
		return fmt.Errorf("updating embedding for content %s: %w", id, err)
	}
	return nil
}

// SimilarContents returns published contents most similar to the given embedding.
func (s *Store) SimilarContents(ctx context.Context, excludeID uuid.UUID, embedding pgvector.Vector, limit int) ([]RelatedContent, error) {
	rows, err := s.q.SimilarContents(ctx, db.SimilarContentsParams{
		TargetEmbedding: embedding,
		ExcludeID:       excludeID,
		MaxResults:      int32(limit), // #nosec G115 -- limit is bounded by handler (max 20)
	})
	if err != nil {
		return nil, fmt.Errorf("querying similar contents: %w", err)
	}
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	topicMap, err := s.topicsForContents(ctx, ids)
	if err != nil {
		return nil, err
	}

	results := make([]RelatedContent, len(rows))
	for i, r := range rows {
		results[i] = RelatedContent{
			Slug:       r.Slug,
			Title:      r.Title,
			Excerpt:    r.Excerpt,
			Type:       Type(r.Type),
			Similarity: r.Similarity,
			Topics:     topicMap[r.ID],
		}
	}
	return results, nil
}

// ContentEmbeddingBySlug returns the ID and embedding for a content by slug.
func (s *Store) ContentEmbeddingBySlug(ctx context.Context, slug string) (uuid.UUID, *pgvector.Vector, error) {
	r, err := s.q.ContentEmbeddingBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, nil, ErrNotFound
		}
		return uuid.Nil, nil, fmt.Errorf("querying embedding for content %s: %w", slug, err)
	}
	return r.ID, r.Embedding, nil
}

// PublishedWithEmbeddings returns all published contents that have embeddings.
func (s *Store) PublishedWithEmbeddings(ctx context.Context) ([]EmbeddingContent, error) {
	rows, err := s.q.PublishedWithEmbeddings(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing published contents with embeddings: %w", err)
	}
	results := make([]EmbeddingContent, len(rows))
	for i, r := range rows {
		results[i] = EmbeddingContent{
			ID:    r.ID,
			Slug:  r.Slug,
			Title: r.Title,
			Type:  Type(r.Type),
		}
		if r.Embedding != nil {
			results[i].Embedding = r.Embedding.Slice()
		}
	}
	return results, nil
}

func (s *Store) DeleteContent(ctx context.Context, id uuid.UUID) error {
	err := s.q.ArchiveContent(ctx, id)
	if err != nil {
		return fmt.Errorf("archiving content %s: %w", id, err)
	}
	return nil
}

// PublishContent sets content status to published.
func (s *Store) PublishContent(ctx context.Context, id uuid.UUID) (*Content, error) {
	r, err := s.q.PublishContent(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("publishing content %s: %w", id, err)
	}

	c := rowToContent(contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status, Source: r.Source, SourceType: r.SourceType,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder, ReviewLevel: r.ReviewLevel,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage, PublishedAt: r.PublishedAt,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})

	topics, err := s.TopicsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Topics = topics

	tags, err := s.TagsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Tags = tags

	return &c, nil
}

// TopicsForContent returns topic references for a content item.
func (s *Store) TopicsForContent(ctx context.Context, contentID uuid.UUID) ([]TopicRef, error) {
	rows, err := s.q.TopicsForContent(ctx, contentID)
	if err != nil {
		return nil, fmt.Errorf("querying topics for content %s: %w", contentID, err)
	}
	refs := make([]TopicRef, len(rows))
	for i, r := range rows {
		refs[i] = TopicRef{ID: r.ID, Slug: r.Slug, Name: r.Name}
	}
	return refs, nil
}

// topicsForContents fetches topics for multiple content IDs in a single query,
// returning a map from content ID to topic refs.
func (s *Store) topicsForContents(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]TopicRef, error) {
	if len(ids) == 0 {
		return map[uuid.UUID][]TopicRef{}, nil
	}
	rows, err := s.q.TopicsForContents(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("batch querying topics: %w", err)
	}
	result := make(map[uuid.UUID][]TopicRef, len(ids))
	for _, r := range rows {
		result[r.ContentID] = append(result[r.ContentID], TopicRef{ID: r.ID, Slug: r.Slug, Name: r.Name})
	}
	return result, nil
}

// contentRow is the common field set shared by all sqlc-generated content row
// types. Callers construct a contentRow from their specific row type, then pass
// it to rowToContent. This eliminates a 21-parameter positional call.
type contentRow struct {
	ID             uuid.UUID
	Slug           string
	Title          string
	Body           string
	Excerpt        string
	Type           db.ContentType
	Status         db.ContentStatus
	Source         *string
	SourceType     db.NullSourceType
	SeriesID       *string
	SeriesOrder    *int32
	ReviewLevel    db.ReviewLevel
	IsPublic       bool
	ProjectID      *uuid.UUID
	AiMetadata     json.RawMessage
	ReadingTimeMin int32
	CoverImage     *string
	PublishedAt    *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func rowToContent(r contentRow) Content { //nolint:gocritic // hugeParam: struct passed by value matches existing pattern across all call sites
	c := Content{
		ID:             r.ID,
		Slug:           r.Slug,
		Title:          r.Title,
		Body:           r.Body,
		Excerpt:        r.Excerpt,
		Type:           Type(r.Type),
		Status:         Status(r.Status),
		Source:         r.Source,
		SourceType:     nullSourceTypeToPtr(r.SourceType),
		ReviewLevel:    ReviewLevel(r.ReviewLevel),
		IsPublic:       r.IsPublic,
		ProjectID:      r.ProjectID,
		AIMetadata:     r.AiMetadata,
		ReadingTimeMin: int(r.ReadingTimeMin),
		CoverImage:     r.CoverImage,
		PublishedAt:    r.PublishedAt,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}
	if r.SeriesID != nil {
		c.SeriesID = r.SeriesID
	}
	if r.SeriesOrder != nil {
		v := int(*r.SeriesOrder)
		c.SeriesOrder = &v
	}
	return c
}

// TagsForContent returns tag slugs for a single content item.
func (s *Store) TagsForContent(ctx context.Context, contentID uuid.UUID) ([]string, error) {
	rows, err := s.q.TagsForContent(ctx, contentID)
	if err != nil {
		return nil, fmt.Errorf("querying tags for content %s: %w", contentID, err)
	}
	tags := make([]string, len(rows))
	for i, r := range rows {
		tags[i] = r.Slug
	}
	return tags, nil
}

// tagsForContents fetches tags for multiple content IDs in a single query,
// returning a map from content ID to tag slugs.
func (s *Store) tagsForContents(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]string, error) {
	if len(ids) == 0 {
		return map[uuid.UUID][]string{}, nil
	}
	rows, err := s.q.TagsForContents(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("batch querying tags: %w", err)
	}
	result := make(map[uuid.UUID][]string, len(ids))
	for _, r := range rows {
		result[r.ContentID] = append(result[r.ContentID], r.Slug)
	}
	return result, nil
}

// SimilarTIL is a TIL content item returned by embedding similarity search.
type SimilarTIL struct {
	Slug       string   `json:"slug"`
	Title      string   `json:"title"`
	Tags       []string `json:"tags"`
	Similarity float64  `json:"similarity"`
}

// SimilarTILs finds TILs semantically similar to the given content by embedding.
// No visibility filter — TILs are private by default.
func (s *Store) SimilarTILs(ctx context.Context, slug string, limit int) ([]SimilarTIL, error) {
	r, err := s.q.ContentEmbeddingBySlugAny(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return []SimilarTIL{}, nil // no embedding → empty results
		}
		return nil, fmt.Errorf("querying embedding for %s: %w", slug, err)
	}
	if r.Embedding == nil {
		return []SimilarTIL{}, nil
	}

	rows, err := s.q.SimilarTILs(ctx, db.SimilarTILsParams{
		TargetEmbedding: *r.Embedding,
		ExcludeID:       r.ID,
		MaxResults:      int32(limit), // #nosec G115 -- limit bounded by handler
	})
	if err != nil {
		return nil, fmt.Errorf("querying similar TILs: %w", err)
	}

	ids := make([]uuid.UUID, len(rows))
	for i := range rows {
		ids[i] = rows[i].ID
	}
	tagMap, err := s.tagsForContents(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("batch loading tags for similar TILs: %w", err)
	}

	results := make([]SimilarTIL, len(rows))
	for i, row := range rows {
		results[i] = SimilarTIL{
			Slug:       row.Slug,
			Title:      row.Title,
			Tags:       tagMap[row.ID],
			Similarity: row.Similarity,
		}
	}
	return results, nil
}

// EmbeddingCandidate is a content record that needs embedding generation.
type EmbeddingCandidate struct {
	ID    uuid.UUID
	Slug  string
	Title string
	Body  string
}

// ContentsWithoutEmbedding returns content records that need embedding generation.
func (s *Store) ContentsWithoutEmbedding(ctx context.Context, limit int32) ([]EmbeddingCandidate, error) {
	rows, err := s.q.ContentsWithoutEmbedding(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("listing contents without embedding: %w", err)
	}
	candidates := make([]EmbeddingCandidate, len(rows))
	for i, r := range rows {
		candidates[i] = EmbeddingCandidate{
			ID:    r.ID,
			Slug:  r.Slug,
			Title: r.Title,
			Body:  r.Body,
		}
	}
	return candidates, nil
}
