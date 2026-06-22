// Copyright 2026 Koopa. All rights reserved.

// Package content manages the public editorial corpus — articles,
// essays, build logs, TILs, and digests — through the draft → review →
// published → archived lifecycle. It owns the contents table end to
// end: admin CRUD, the anonymous read surface with RSS and sitemap
// syndication for published rows, search integration, and the pgvector
// embedding columns behind the knowledge graph.
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

	"github.com/Koopa0/koopa/internal/db"
)

// Type represents a content type.
type Type string

const (
	TypeArticle  Type = "article"
	TypeEssay    Type = "essay"
	TypeBuildLog Type = "build-log"
	TypeTIL      Type = "til"
	TypeDigest   Type = "digest"
	// TypeNote has been removed — notes are a separate entity
	// now (internal/note, notes table). The content_type ENUM no longer
	// accepts 'note'. Use note.Kind for note sub-type typed aliases.
	// TypeBookmark was split out earlier into the bookmarks table; the
	// bookmark feature was later removed entirely.
)

// Valid reports whether t is a known content type.
func (t Type) Valid() bool {
	switch t {
	case TypeArticle, TypeEssay, TypeBuildLog, TypeTIL, TypeDigest:
		return true
	default:
		return false
	}
}

// Status represents a content status.
type Status string

const (
	StatusDraft     Status = "draft"
	StatusReview    Status = "review"
	StatusPublished Status = "published"
	StatusArchived  Status = "archived"
)

// TopicRef is a lightweight topic reference embedded in content.
type TopicRef struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
	Name string    `json:"name"`
}

// Content represents a piece of content.
type Content struct {
	ID             uuid.UUID       `json:"id"`
	Slug           string          `json:"slug"`
	Title          string          `json:"title"`
	Body           string          `json:"body"`
	Excerpt        string          `json:"excerpt"`
	Type           Type            `json:"type"`
	Status         Status          `json:"status"`
	Topics         []TopicRef      `json:"topics"`
	SeriesID       *string         `json:"series_id,omitempty"`
	SeriesOrder    *int            `json:"series_order,omitempty"`
	IsPublic       bool            `json:"is_public"`
	ProjectID      *uuid.UUID      `json:"project_id,omitempty"`
	AIMetadata     json.RawMessage `json:"ai_metadata,omitempty"`
	ReadingTimeMin int             `json:"reading_time_min"`
	CoverImage     *string         `json:"cover_image,omitempty"`
	// CreatedBy is the proposing agent for agent-pushed content (the MCP
	// propose_content tool stamps the caller identity here). NULL for
	// owner/admin-authored content.
	CreatedBy *string `json:"created_by,omitempty"`
	// ProposalRationale is the proposing agent's "why I propose this" note,
	// surfaced in the admin review queue. NULL for admin-authored content.
	ProposalRationale *string    `json:"proposal_rationale,omitempty"`
	PublishedAt       *time.Time `json:"published_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// Brief is the minimal content projection used when a consumer only needs
// display fields (id, slug, title, type). The admin project detail endpoint
// ships this shape rather than the full Content so project responses stay
// lean and don't carry bodies across the wire.
type Brief struct {
	ID    uuid.UUID `json:"id"`
	Slug  string    `json:"slug"`
	Title string    `json:"title"`
	Type  Type      `json:"type"`
}

// PublicFilter parameterises the anonymous read surface — the /api/
// routes that render published-and-public content. The handler layer
// pairs it with PublicContents / Search / RSS.
type PublicFilter struct {
	Page    int
	PerPage int
	Type    *Type
	Since   *time.Time
}

// Filter parameterises the authenticated admin listing. Every field is
// optional; zero / nil means "no constraint on that column".
type Filter struct {
	Page     int
	PerPage  int
	Type     *Type
	Status   *Status
	IsPublic *bool
	Project  *uuid.UUID
}

// CreateParams are the parameters for creating content.
type CreateParams struct {
	Slug           string          `json:"slug"`
	Title          string          `json:"title"`
	Body           string          `json:"body"`
	Excerpt        string          `json:"excerpt"`
	Type           Type            `json:"type"`
	Status         Status          `json:"status"`
	TopicIDs       []uuid.UUID     `json:"topic_ids"`
	SeriesID       *string         `json:"series_id,omitempty"`
	SeriesOrder    *int            `json:"series_order,omitempty"`
	IsPublic       bool            `json:"is_public"`
	ProjectID      *uuid.UUID      `json:"project_id,omitempty"`
	AIMetadata     json.RawMessage `json:"ai_metadata,omitempty"`
	ReadingTimeMin int             `json:"reading_time_min"`
	CoverImage     *string         `json:"cover_image,omitempty"`
	// CreatedBy stamps the proposing agent on agent-pushed content. The MCP
	// propose_content tool sets it to the resolved caller identity; the admin
	// HTTP Create path leaves it nil (owner-authored content has no agent
	// author — it is NOT forced to 'human').
	CreatedBy *string `json:"created_by,omitempty"`
	// ProposalRationale carries the proposing agent's justification. Set by
	// propose_content, nil for admin-authored content.
	ProposalRationale *string `json:"proposal_rationale,omitempty"`
}

// UpdateParams are the parameters for updating content.
type UpdateParams struct {
	Slug           *string         `json:"slug,omitempty"`
	Title          *string         `json:"title,omitempty"`
	Body           *string         `json:"body,omitempty"`
	Excerpt        *string         `json:"excerpt,omitempty"`
	Type           *Type           `json:"type,omitempty"`
	Status         *Status         `json:"status,omitempty"`
	TopicIDs       []uuid.UUID     `json:"topic_ids,omitempty"`
	SeriesID       *string         `json:"series_id,omitempty"`
	SeriesOrder    *int            `json:"series_order,omitempty"`
	IsPublic       *bool           `json:"is_public,omitempty"`
	ProjectID      *uuid.UUID      `json:"project_id,omitempty"`
	AIMetadata     json.RawMessage `json:"ai_metadata,omitempty"`
	ReadingTimeMin *int            `json:"reading_time_min,omitempty"`
	CoverImage     *string         `json:"cover_image,omitempty"`
}

// RelatedContent is a content item with a similarity score.
type RelatedContent struct {
	Slug       string     `json:"slug"`
	Title      string     `json:"title"`
	Excerpt    string     `json:"excerpt"`
	Type       Type       `json:"type"`
	Similarity float64    `json:"similarity"`
	Topics     []TopicRef `json:"topics"`
}

// GraphNode represents a node in the knowledge graph.
type GraphNode struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Type        string `json:"type"`
	ContentType string `json:"content_type,omitempty"`
	Topic       string `json:"topic,omitempty"`
	Count       int    `json:"count,omitempty"`
}

// GraphLink represents an edge in the knowledge graph.
type GraphLink struct {
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	Type       string   `json:"type"`
	Similarity *float64 `json:"similarity,omitempty"`
}

// KnowledgeGraph is the full graph response.
type KnowledgeGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Links []GraphLink `json:"links"`
}

// EmbeddingContent holds a published content with its embedding vector for graph computation.
type EmbeddingContent struct {
	ID        uuid.UUID
	Slug      string
	Title     string
	Type      Type
	Embedding []float32
}

var (
	// ErrNotFound indicates the content does not exist.
	ErrNotFound = errors.New("content: not found")

	// ErrConflict indicates a generic unique-constraint violation.
	// Use SlugConflictError specifically for slug collisions — it carries
	// the existing row's identity so callers can decide whether to
	// update or pick a new slug.
	ErrConflict = errors.New("content: conflict")

	// ErrInvalidInput signals a client-supplied value the database rejected:
	// a foreign key pointing at a non-existent row (e.g. a stale project_id)
	// or a check-constraint violation (slug format, series_id/series_order
	// pairing).
	ErrInvalidInput = errors.New("content: invalid input")

	// ErrInvalidState signals a state-machine rejection: the requested
	// transition is not valid for the content's current status.
	// SubmitForReview (draft→review) and RevertToDraft (review→draft)
	// surface this when the conditional UPDATE matches zero rows.
	ErrInvalidState = errors.New("content: invalid state for transition")

	// ErrNotTransactional indicates a multi-row write (the content row plus
	// the content_topics junction) was invoked on a
	// non-transactional store. Production admin routes always bind a tx via
	// api.ActorMiddleware; surfacing this as a 500 turns a wiring bug into a
	// loud failure instead of a silent partial write. Mirrors feed.Store.
	ErrNotTransactional = errors.New("content: mutation requires a transactional store")
)

// SlugConflictError is returned by CreateContent when the new slug collides
// with an existing contents row. Callers (notably learning-studio via MCP)
// use Slug + ContentID to decide whether the conflict represents an update
// target (same logical note, fetch and update) or a revisit that needs a
// new slug (with a -v2 / -revisit-<date> suffix).
type SlugConflictError struct {
	Slug      string
	ContentID uuid.UUID
}

func (e *SlugConflictError) Error() string {
	return fmt.Sprintf("content: slug %q already in use (existing %s)", e.Slug, e.ContentID)
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

// Store handles database operations for content.
type Store struct {
	dbtx db.DBTX
	q    *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{dbtx: dbtx, q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by callers
// composing multi-store transactions — typically via api.ActorMiddleware
// (HTTP) or mcp.Server.withActorTx (MCP). The tx carries koopa.actor
// so audit triggers attribute mutations correctly.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{dbtx: tx, q: s.q.WithTx(tx)}
}

// mapWriteError classifies a PostgreSQL content-write failure into a store
// sentinel. A unique violation (23505) on the slug produces *SlugConflictError
// when the caller has pre-resolved the existing id, else the bare ErrConflict;
// a foreign-key (23503) or check-constraint (23514) violation becomes
// ErrInvalidInput; any other error is wrapped with the supplied context.
//
// The pre-resolved id MUST be captured BEFORE the INSERT that produced err
// — once the outer tx hits 23505, PostgreSQL marks it aborted and any
// subsequent SELECT returns SQLSTATE 25P02 ("current transaction is
// aborted"). That is why the lookup cannot live in this helper.
func mapWriteError(err error, slug string, existingID uuid.UUID, operation string) error {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		return fmt.Errorf("%s: %w", operation, err)
	}
	switch pgErr.Code {
	case pgerrcode.UniqueViolation:
		if pgErr.ConstraintName != "contents_slug_key" || existingID == uuid.Nil {
			return ErrConflict
		}
		return &SlugConflictError{Slug: slug, ContentID: existingID}
	case pgerrcode.ForeignKeyViolation, pgerrcode.CheckViolation:
		return ErrInvalidInput
	default:
		return fmt.Errorf("%s: %w", operation, err)
	}
}

// preResolveSlugID looks up the existing content id for a slug so
// CreateContent/UpdateContent can produce a structured SlugConflictError
// when the INSERT/UPDATE hits 23505. Missing rows and query errors both
// return uuid.Nil without error — the subsequent write is authoritative.
func (s *Store) preResolveSlugID(ctx context.Context, slug string) uuid.UUID {
	if slug == "" {
		return uuid.Nil
	}
	id, err := s.q.ContentIDBySlug(ctx, slug)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// BriefsByProjectID returns content briefs linked to a project, newest first.
// Used by the admin project detail endpoint to populate related_content
// without shipping full bodies.
func (s *Store) BriefsByProjectID(ctx context.Context, projectID uuid.UUID) ([]Brief, error) {
	rows, err := s.q.ContentBriefsByProjectID(ctx, &projectID)
	if err != nil {
		return nil, fmt.Errorf("listing content briefs for project %s: %w", projectID, err)
	}
	briefs := make([]Brief, len(rows))
	for i := range rows {
		r := &rows[i]
		briefs[i] = Brief{
			ID:    r.ID,
			Slug:  r.Slug,
			Title: r.Title,
			Type:  Type(r.Type),
		}
	}
	return briefs, nil
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
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		CreatedBy: r.CreatedBy, ProposalRationale: r.ProposalRationale,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})

	topics, err := s.TopicsForContent(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	c.Topics = topics

	return &c, nil
}

// PublicContents returns a paginated list of published-and-public
// contents. The public /api/contents surface consumes this.
func (s *Store) PublicContents(ctx context.Context, f PublicFilter) ([]Content, int, error) {
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
			Type: r.Type, Status: r.Status,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
			PublishedAt: r.PublishedAt,
			CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
		ids[i] = r.ID
	}

	if err := s.attachBatchTopics(ctx, contents, ids); err != nil {
		return nil, 0, err
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
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})

	topics, err := s.TopicsForContent(ctx, c.ID)
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
			Type: r.Type, Status: r.Status,
			SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
			IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
			ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
			PublishedAt: r.PublishedAt,
			CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
		ids[i] = r.ID
	}

	if err := s.attachBatchTopics(ctx, contents, ids); err != nil {
		return nil, 0, err
	}

	return contents, int(count), nil
}

// CreateContent inserts a new content row and synchronously wires the
// associated content_topics junction writes. All writes run on the DBTX
// passed in at Store construction — callers own the transaction boundary.
// For atomic behavior, construct the Store with a pgx.Tx (HTTP handler
// opens one from the pool; MCP uses withActorTx).
//
// Slug collisions return *SlugConflictError carrying the existing row's ID
// so callers can decide whether to update or pick a new slug (see
// Koopa-Learning.md Step 9 revisit policy). Other unique violations
// return the bare ErrConflict.
func (s *Store) CreateContent(ctx context.Context, p *CreateParams) (*Content, error) {
	// Atomicity: the content row plus its content_topics junction rows must
	// be written on one transaction so a junction failure rolls back the
	// row. Reject a non-tx store before any write rather than leaving an
	// orphan row with partial junctions.
	if len(p.TopicIDs) > 0 {
		if _, ok := s.dbtx.(pgx.Tx); !ok {
			return nil, ErrNotTransactional
		}
	}

	var seriesOrder *int32
	if p.SeriesOrder != nil {
		v := int32(*p.SeriesOrder) // #nosec G115 -- series order is a small sequential value, not user-controlled
		seriesOrder = &v
	}

	// Resolve the existing slug id BEFORE the INSERT. A 23505 inside a
	// caller-supplied pgx.Tx aborts the transaction, so the lookup cannot
	// happen after the failed INSERT. The INSERT itself remains the
	// authoritative uniqueness check; this is a best-effort enrichment so
	// the caller receives a structured SlugConflictError instead of the
	// bare ErrConflict.
	preResolvedID := s.preResolveSlugID(ctx, p.Slug)

	r, err := s.q.CreateContent(ctx, db.CreateContentParams{
		Slug:              p.Slug,
		Title:             p.Title,
		Body:              p.Body,
		Excerpt:           p.Excerpt,
		Type:              db.ContentType(p.Type),
		Status:            db.ContentStatus(p.Status),
		SeriesID:          p.SeriesID,
		SeriesOrder:       seriesOrder,
		IsPublic:          p.IsPublic,
		ProjectID:         p.ProjectID,
		AiMetadata:        p.AIMetadata,
		ReadingTimeMin:    int32(p.ReadingTimeMin), // #nosec G115 -- reading time in minutes is bounded, not user-controlled
		CoverImage:        p.CoverImage,
		CreatedBy:         p.CreatedBy,
		ProposalRationale: p.ProposalRationale,
	})
	if err != nil {
		return nil, mapWriteError(err, p.Slug, preResolvedID, "creating content")
	}

	for _, topicID := range p.TopicIDs {
		if topicErr := s.q.AddContentTopic(ctx, db.AddContentTopicParams{
			ContentID: r.ID,
			TopicID:   topicID,
		}); topicErr != nil {
			return nil, fmt.Errorf("adding content topic: %w", topicErr)
		}
	}

	c := rowToContent(contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		CreatedBy: r.CreatedBy, ProposalRationale: r.ProposalRationale,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})

	// Topic fetch runs on the caller's tx; a read failure aborts that tx,
	// so it MUST propagate. Masking it as an empty-collection success would let
	// the handler emit 2xx before the middleware's commit fails — an
	// inconsistency the client never hears about.
	topics, err := s.TopicsForContent(ctx, c.ID)
	if err != nil {
		return nil, fmt.Errorf("fetching topics for content %s: %w", c.ID, err)
	}
	c.Topics = topics

	return &c, nil
}

// UpdateContent updates a content row and optionally replaces its topic
// associations. All writes run on the DBTX provided at Store construction;
// the caller owns the transaction boundary. Pass a pgx.Tx when you need
// atomic update + topic replacement.
func (s *Store) UpdateContent(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Content, error) {
	// Atomicity: when TopicIDs is non-nil the update does DELETE-then-INSERT
	// on content_topics alongside the content UPDATE; reject a non-tx store
	// so the topic replacement cannot half-apply.
	if p.TopicIDs != nil {
		if _, ok := s.dbtx.(pgx.Tx); !ok {
			return nil, ErrNotTransactional
		}
	}

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

	var (
		slug          string
		preResolvedID uuid.UUID
	)
	if p.Slug != nil {
		slug = *p.Slug
		preResolvedID = s.preResolveSlugID(ctx, slug)
	}

	r, err := s.q.UpdateContent(ctx, db.UpdateContentParams{
		ID:             id,
		Slug:           p.Slug,
		Title:          p.Title,
		Body:           p.Body,
		Excerpt:        p.Excerpt,
		ContentType:    nullContentType(p.Type),
		Status:         nullContentStatus(p.Status),
		SeriesID:       p.SeriesID,
		SeriesOrder:    seriesOrder,
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
		return nil, mapWriteError(err, slug, preResolvedID, fmt.Sprintf("updating content %s", id))
	}

	if p.TopicIDs != nil {
		if deleteErr := s.q.DeleteContentTopics(ctx, id); deleteErr != nil {
			return nil, fmt.Errorf("clearing content topics: %w", deleteErr)
		}
		for _, topicID := range p.TopicIDs {
			if topicErr := s.q.AddContentTopic(ctx, db.AddContentTopicParams{
				ContentID: id,
				TopicID:   topicID,
			}); topicErr != nil {
				return nil, fmt.Errorf("adding content topic: %w", topicErr)
			}
		}
	}

	c := rowToContent(contentRow{
		ID: r.ID, Slug: r.Slug, Title: r.Title, Body: r.Body, Excerpt: r.Excerpt,
		Type: r.Type, Status: r.Status,
		SeriesID: r.SeriesID, SeriesOrder: r.SeriesOrder,
		IsPublic: r.IsPublic, ProjectID: r.ProjectID, AiMetadata: r.AiMetadata,
		ReadingTimeMin: r.ReadingTimeMin, CoverImage: r.CoverImage,
		PublishedAt: r.PublishedAt,
		CreatedAt:   r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})

	// Topic fetch runs on the caller's STILL-OPEN tx (not post-commit); a
	// read failure aborts that tx, so it MUST propagate. Masking it as an
	// empty-collection success would let the handler emit 2xx before the
	// middleware's commit fails.
	topics, err := s.TopicsForContent(ctx, c.ID)
	if err != nil {
		return nil, fmt.Errorf("fetching topics for content %s: %w", c.ID, err)
	}
	c.Topics = topics

	return &c, nil
}

func (s *Store) DeleteContent(ctx context.Context, id uuid.UUID) error {
	err := s.q.ArchiveContent(ctx, id)
	if err != nil {
		return fmt.Errorf("archiving content %s: %w", id, err)
	}
	return nil
}

// attachBatchTopics populates Topics for a list of content rows with one
// batch query instead of N round-trips. Every entry in out gets a non-nil
// Topics slice (the loader pre-inits empty slices for IDs with zero rows),
// so the wire shape is always [] rather than null. ids must be aligned
// with out: ids[i] is the ID of out[i].
func (s *Store) attachBatchTopics(ctx context.Context, out []Content, ids []uuid.UUID) error {
	if len(out) == 0 {
		return nil
	}
	topicMap, err := s.topicsForContents(ctx, ids)
	if err != nil {
		return err
	}
	for i := range out {
		out[i].Topics = topicMap[out[i].ID]
	}
	return nil
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
// returning a map from content ID to topic refs. Every requested ID is
// guaranteed to be present in the result map — IDs with zero topics map to
// an empty (non-nil) slice so JSON marshaling emits "topics": [] rather
// than "topics": null. Callers can assign the map value directly to a
// Content.Topics field without a nil check.
func (s *Store) topicsForContents(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]TopicRef, error) {
	if len(ids) == 0 {
		return map[uuid.UUID][]TopicRef{}, nil
	}
	rows, err := s.q.TopicsForContents(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("batch querying topics: %w", err)
	}
	result := make(map[uuid.UUID][]TopicRef, len(ids))
	for _, id := range ids {
		result[id] = []TopicRef{}
	}
	for _, r := range rows {
		result[r.ContentID] = append(result[r.ContentID], TopicRef{ID: r.ID, Slug: r.Slug, Name: r.Name})
	}
	return result, nil
}

// contentRow is the common field set shared by all sqlc-generated content row
// types. Callers construct a contentRow from their specific row type, then pass
// it to rowToContent. This eliminates a 21-parameter positional call.
type contentRow struct {
	ID                uuid.UUID
	Slug              string
	Title             string
	Body              string
	Excerpt           string
	Type              db.ContentType
	Status            db.ContentStatus
	SeriesID          *string
	SeriesOrder       *int32
	IsPublic          bool
	ProjectID         *uuid.UUID
	AiMetadata        json.RawMessage
	ReadingTimeMin    int32
	CoverImage        *string
	CreatedBy         *string
	ProposalRationale *string
	PublishedAt       *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func rowToContent(r contentRow) Content { //nolint:gocritic // hugeParam: struct passed by value matches existing pattern across all call sites
	c := Content{
		ID:                r.ID,
		Slug:              r.Slug,
		Title:             r.Title,
		Body:              r.Body,
		Excerpt:           r.Excerpt,
		Type:              Type(r.Type),
		Status:            Status(r.Status),
		IsPublic:          r.IsPublic,
		ProjectID:         r.ProjectID,
		AIMetadata:        r.AiMetadata,
		ReadingTimeMin:    int(r.ReadingTimeMin),
		CoverImage:        r.CoverImage,
		CreatedBy:         r.CreatedBy,
		ProposalRationale: r.ProposalRationale,
		PublishedAt:       r.PublishedAt,
		CreatedAt:         r.CreatedAt,
		UpdatedAt:         r.UpdatedAt,
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
