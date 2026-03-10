package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/db"
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
	pool *pgxpool.Pool
	q    *db.Queries
}

// NewStore returns a Store backed by the given pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, q: db.New(pool)}
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

	c := rowToContent(r.ID, r.Slug, r.Title, r.Body, r.Excerpt,
		string(r.Type), string(r.Status), r.Tags, r.Source, nullSourceTypeToPtr(r.SourceType),
		r.SeriesID, r.SeriesOrder, string(r.ReviewLevel), r.AiMetadata,
		r.ReadingTime, r.CoverImage, r.PublishedAt, r.CreatedAt, r.UpdatedAt)

	topics, err := s.topicsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Topics = topics

	return &c, nil
}

// Contents returns a paginated list of published contents.
func (s *Store) Contents(ctx context.Context, f Filter) ([]Content, int, error) {
	ct := nullContentType(f.Type)

	rows, err := s.q.PublishedContents(ctx, db.PublishedContentsParams{
		Limit:       int32(f.PerPage),                //nolint:gosec // pagination values are bounded by API layer
		Offset:      int32((f.Page - 1) * f.PerPage), //nolint:gosec // pagination values are bounded by API layer
		ContentType: ct,
		Tag:         f.Tag,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing contents: %w", err)
	}

	countRow, err := s.q.PublishedContentsCount(ctx, db.PublishedContentsCountParams{
		ContentType: ct,
		Tag:         f.Tag,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("counting contents: %w", err)
	}

	contents := make([]Content, len(rows))
	for i, r := range rows {
		contents[i] = rowToContent(r.ID, r.Slug, r.Title, r.Body, r.Excerpt,
			string(r.Type), string(r.Status), r.Tags, r.Source, nullSourceTypeToPtr(r.SourceType),
			r.SeriesID, r.SeriesOrder, string(r.ReviewLevel), r.AiMetadata,
			r.ReadingTime, r.CoverImage, r.PublishedAt, r.CreatedAt, r.UpdatedAt)
	}

	// populate topics for each content
	for i := range contents {
		topics, err := s.topicsForContent(ctx, contents[i].ID)
		if err != nil {
			return nil, 0, err
		}
		contents[i].Topics = topics
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

	c := rowToContent(r.ID, r.Slug, r.Title, r.Body, r.Excerpt,
		string(r.Type), string(r.Status), r.Tags, r.Source, nullSourceTypeToPtr(r.SourceType),
		r.SeriesID, r.SeriesOrder, string(r.ReviewLevel), r.AiMetadata,
		r.ReadingTime, r.CoverImage, r.PublishedAt, r.CreatedAt, r.UpdatedAt)

	topics, err := s.topicsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Topics = topics

	return &c, nil
}

// ContentsByTopicID returns published contents for a topic.
func (s *Store) ContentsByTopicID(ctx context.Context, topicID uuid.UUID, page, perPage int) ([]Content, int, error) {
	rows, err := s.q.ContentsByTopicID(ctx, db.ContentsByTopicIDParams{
		TopicID: topicID,
		Limit:   int32(perPage),              //nolint:gosec // pagination values are bounded by API layer
		Offset:  int32((page - 1) * perPage), //nolint:gosec // pagination values are bounded by API layer
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing contents by topic: %w", err)
	}

	count, err := s.q.ContentsByTopicIDCount(ctx, topicID)
	if err != nil {
		return nil, 0, fmt.Errorf("counting contents by topic: %w", err)
	}

	contents := make([]Content, len(rows))
	for i, r := range rows {
		contents[i] = rowToContent(r.ID, r.Slug, r.Title, r.Body, r.Excerpt,
			string(r.Type), string(r.Status), r.Tags, r.Source, nullSourceTypeToPtr(r.SourceType),
			r.SeriesID, r.SeriesOrder, string(r.ReviewLevel), r.AiMetadata,
			r.ReadingTime, r.CoverImage, r.PublishedAt, r.CreatedAt, r.UpdatedAt)
	}

	return contents, int(count), nil
}

// Search performs full-text search on published content.
func (s *Store) Search(ctx context.Context, query string, page, perPage int) ([]Content, int, error) {
	rows, err := s.q.SearchContents(ctx, db.SearchContentsParams{
		WebsearchToTsquery: query,
		Limit:              int32(perPage),              //nolint:gosec // pagination values are bounded by API layer
		Offset:             int32((page - 1) * perPage), //nolint:gosec // pagination values are bounded by API layer
	})
	if err != nil {
		return nil, 0, fmt.Errorf("searching contents: %w", err)
	}

	count, err := s.q.SearchContentsCount(ctx, query)
	if err != nil {
		return nil, 0, fmt.Errorf("counting search results: %w", err)
	}

	contents := make([]Content, len(rows))
	for i, r := range rows {
		contents[i] = rowToContent(r.ID, r.Slug, r.Title, r.Body, r.Excerpt,
			string(r.Type), string(r.Status), r.Tags, r.Source, nullSourceTypeToPtr(r.SourceType),
			r.SeriesID, r.SeriesOrder, string(r.ReviewLevel), r.AiMetadata,
			r.ReadingTime, r.CoverImage, r.PublishedAt, r.CreatedAt, r.UpdatedAt)
	}

	return contents, int(count), nil
}

// PublishedForRSS returns recent published content for RSS feed.
func (s *Store) PublishedForRSS(ctx context.Context, limit int) ([]Content, error) {
	rows, err := s.q.PublishedForRSS(ctx, int32(limit)) //nolint:gosec // RSS limit is a small constant, not user-controlled
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

// CreateContent inserts a new content and associates topics.
func (s *Store) CreateContent(ctx context.Context, p CreateParams) (*Content, error) {
	var seriesOrder *int32
	if p.SeriesOrder != nil {
		v := int32(*p.SeriesOrder) //nolint:gosec // series order is a small sequential value, not user-controlled
		seriesOrder = &v
	}
	r, err := s.q.CreateContent(ctx, db.CreateContentParams{
		Slug:        p.Slug,
		Title:       p.Title,
		Body:        p.Body,
		Excerpt:     p.Excerpt,
		Type:        db.ContentType(p.Type),
		Status:      db.ContentStatus(p.Status),
		Tags:        p.Tags,
		Source:      p.Source,
		SourceType:  nullSourceType(p.SourceType),
		SeriesID:    p.SeriesID,
		SeriesOrder: seriesOrder,
		ReviewLevel: db.ReviewLevel(p.ReviewLevel),
		AiMetadata:  p.AIMetadata,
		ReadingTime: int32(p.ReadingTime), //nolint:gosec // reading time in minutes is bounded, not user-controlled
		CoverImage:  p.CoverImage,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating content: %w", err)
	}

	for _, topicID := range p.TopicIDs {
		if err := s.q.AddContentTopic(ctx, db.AddContentTopicParams{
			ContentID: r.ID,
			TopicID:   topicID,
		}); err != nil {
			return nil, fmt.Errorf("adding content topic: %w", err)
		}
	}

	c := rowToContent(r.ID, r.Slug, r.Title, r.Body, r.Excerpt,
		string(r.Type), string(r.Status), r.Tags, r.Source, nullSourceTypeToPtr(r.SourceType),
		r.SeriesID, r.SeriesOrder, string(r.ReviewLevel), r.AiMetadata,
		r.ReadingTime, r.CoverImage, r.PublishedAt, r.CreatedAt, r.UpdatedAt)

	topics, err := s.topicsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Topics = topics

	return &c, nil
}

// UpdateContent updates a content and replaces topic associations.
func (s *Store) UpdateContent(ctx context.Context, id uuid.UUID, p UpdateParams) (*Content, error) {
	var readingTime *int32
	if p.ReadingTime != nil {
		v := int32(*p.ReadingTime) //nolint:gosec // reading time in minutes is bounded, not user-controlled
		readingTime = &v
	}
	var seriesOrder *int32
	if p.SeriesOrder != nil {
		v := int32(*p.SeriesOrder) //nolint:gosec // series order is a small sequential value, not user-controlled
		seriesOrder = &v
	}

	r, err := s.q.UpdateContent(ctx, db.UpdateContentParams{
		ID:          id,
		Slug:        p.Slug,
		Title:       p.Title,
		Body:        p.Body,
		Excerpt:     p.Excerpt,
		ContentType: nullContentType(p.Type),
		Status:      nullContentStatus(p.Status),
		Tags:        p.Tags,
		Source:      p.Source,
		SourceType:  nullSourceType(p.SourceType),
		SeriesID:    p.SeriesID,
		SeriesOrder: seriesOrder,
		ReviewLevel: nullReviewLevel(p.ReviewLevel),
		AiMetadata:  p.AIMetadata,
		ReadingTime: readingTime,
		CoverImage:  p.CoverImage,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("updating content %s: %w", id, err)
	}

	if p.TopicIDs != nil {
		if err := s.q.SetContentTopics(ctx, id); err != nil {
			return nil, fmt.Errorf("clearing content topics: %w", err)
		}
		for _, topicID := range p.TopicIDs {
			if err := s.q.AddContentTopic(ctx, db.AddContentTopicParams{
				ContentID: id,
				TopicID:   topicID,
			}); err != nil {
				return nil, fmt.Errorf("adding content topic: %w", err)
			}
		}
	}

	c := rowToContent(r.ID, r.Slug, r.Title, r.Body, r.Excerpt,
		string(r.Type), string(r.Status), r.Tags, r.Source, nullSourceTypeToPtr(r.SourceType),
		r.SeriesID, r.SeriesOrder, string(r.ReviewLevel), r.AiMetadata,
		r.ReadingTime, r.CoverImage, r.PublishedAt, r.CreatedAt, r.UpdatedAt)

	topics, err := s.topicsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Topics = topics

	return &c, nil
}

// DeleteContent soft-deletes content by setting status to archived.
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

	c := rowToContent(r.ID, r.Slug, r.Title, r.Body, r.Excerpt,
		string(r.Type), string(r.Status), r.Tags, r.Source, nullSourceTypeToPtr(r.SourceType),
		r.SeriesID, r.SeriesOrder, string(r.ReviewLevel), r.AiMetadata,
		r.ReadingTime, r.CoverImage, r.PublishedAt, r.CreatedAt, r.UpdatedAt)

	topics, err := s.topicsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Topics = topics

	return &c, nil
}

func (s *Store) topicsForContent(ctx context.Context, contentID uuid.UUID) ([]TopicRef, error) {
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

func rowToContent(
	id uuid.UUID, slug, title, body, excerpt string,
	typ, status string, tags []string,
	source *string, sourceType *SourceType, seriesID *string, seriesOrder *int32,
	reviewLevel string, aiMetadata json.RawMessage,
	readingTime int32, coverImage *string, publishedAt *time.Time,
	createdAt, updatedAt time.Time,
) Content {
	c := Content{
		ID:          id,
		Slug:        slug,
		Title:       title,
		Body:        body,
		Excerpt:     excerpt,
		Type:        Type(typ),
		Status:      Status(status),
		Tags:        tags,
		Source:      source,
		SourceType:  sourceType,
		ReviewLevel: ReviewLevel(reviewLevel),
		AIMetadata:  aiMetadata,
		ReadingTime: int(readingTime),
		CoverImage:  coverImage,
		PublishedAt: publishedAt,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
	if seriesID != nil {
		c.SeriesID = seriesID
	}
	if seriesOrder != nil {
		v := int(*seriesOrder)
		c.SeriesOrder = &v
	}
	return c
}
