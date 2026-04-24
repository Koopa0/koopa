-- name: ContentByID :one
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents WHERE id = $1;

-- name: PublishedContents :many
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('since')::timestamptz IS NULL OR published_at >= sqlc.narg('since'))
ORDER BY published_at DESC NULLS LAST
LIMIT $1 OFFSET $2;

-- name: PublishedContentsCount :one
SELECT COUNT(*) FROM contents
WHERE status = 'published' AND is_public = true
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('since')::timestamptz IS NULL OR published_at >= sqlc.narg('since'));

-- name: ContentBySlug :one
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents WHERE slug = $1;

-- name: ContentsByTopicID :many
SELECT c.id, c.slug, c.title, c.body, c.excerpt, c.type, c.status,
       c.series_id, c.series_order,
       c.is_public, c.project_id, c.ai_metadata, c.reading_time_min, c.cover_image,
       c.published_at, c.created_at, c.updated_at
FROM contents c
JOIN content_topics ct ON ct.content_id = c.id
WHERE ct.topic_id = $1 AND c.status = 'published' AND c.is_public = true
ORDER BY c.published_at DESC NULLS LAST
LIMIT $2 OFFSET $3;

-- name: ContentsByTopicIDCount :one
SELECT COUNT(*) FROM contents c
JOIN content_topics ct ON ct.content_id = c.id
WHERE ct.topic_id = $1 AND c.status = 'published' AND c.is_public = true;

-- name: SearchContents :many
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
  AND search_vector @@ websearch_to_tsquery('simple', $1)
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
ORDER BY ts_rank(search_vector, websearch_to_tsquery('simple', $1)) DESC
LIMIT $2 OFFSET $3;

-- name: SearchContentsCount :one
SELECT COUNT(*) FROM contents
WHERE status = 'published' AND is_public = true
  AND search_vector @@ websearch_to_tsquery('simple', $1)
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'));

-- name: InternalSearchContents :many
-- Internal search without visibility filter (for MCP tools). Excludes archived.
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status != 'archived'
  AND search_vector @@ websearch_to_tsquery('simple', $1)
ORDER BY ts_rank(search_vector, websearch_to_tsquery('simple', $1)) DESC
LIMIT $2 OFFSET $3;

-- name: InternalSearchContentsCount :one
SELECT COUNT(*) FROM contents
WHERE status != 'archived'
  AND search_vector @@ websearch_to_tsquery('simple', $1);

-- name: InternalSemanticSearchContents :many
-- Semantic search over all contents via pgvector cosine distance. Mirrors
-- InternalSearchContents visibility (excludes only 'archived'); does NOT
-- exclude an anchor content id the way SimilarContents does, because this
-- is called from search_knowledge where there is no "current" content.
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at,
       (1 - (embedding <=> @target_embedding::vector))::float8 AS similarity
FROM contents
WHERE status != 'archived'
  AND embedding IS NOT NULL
ORDER BY embedding <=> @target_embedding::vector
LIMIT @max_results;

-- name: PublishedForRSS :many
SELECT id, slug, title, excerpt, type, published_at, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
ORDER BY published_at DESC NULLS LAST
LIMIT $1;

-- name: ListContents :many
-- Admin list: all statuses, with optional type, status, and is_public filter.
SELECT id, slug, title, excerpt, type, status, is_public, project_id,
       reading_time_min, published_at, created_at, updated_at
FROM contents
WHERE (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('content_status')::content_status IS NULL OR status = sqlc.narg('content_status'))
  AND (sqlc.narg('is_public')::bool IS NULL OR is_public = sqlc.narg('is_public'))
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountContents :one
SELECT COUNT(*) FROM contents
WHERE (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('content_status')::content_status IS NULL OR status = sqlc.narg('content_status'))
  AND (sqlc.narg('is_public')::bool IS NULL OR is_public = sqlc.narg('is_public'));

-- name: AllPublishedSlugs :many
SELECT slug, type, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
ORDER BY updated_at DESC;

-- name: ContentBriefsByProjectID :many
-- Minimal content projection (id, slug, title, type) linked to a project. Used
-- by the admin project detail endpoint to render the "related content" list
-- without pulling full bodies across the wire.
SELECT id, slug, title, type
FROM contents
WHERE project_id = @project_id
ORDER BY created_at DESC;

-- name: CreateContent :one
INSERT INTO contents (slug, title, body, excerpt, type, status,
                      series_id, series_order, is_public, project_id, ai_metadata,
                      reading_time_min, cover_image)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: UpdateContent :one
UPDATE contents SET
    slug = COALESCE(sqlc.narg('slug'), slug),
    title = COALESCE(sqlc.narg('title'), title),
    body = COALESCE(sqlc.narg('body'), body),
    excerpt = COALESCE(sqlc.narg('excerpt'), excerpt),
    type = COALESCE(sqlc.narg('content_type')::content_type, type),
    status = COALESCE(sqlc.narg('status')::content_status, status),
    series_id = COALESCE(sqlc.narg('series_id'), series_id),
    series_order = COALESCE(sqlc.narg('series_order'), series_order),
    is_public = COALESCE(sqlc.narg('is_public'), is_public),
    project_id = COALESCE(sqlc.narg('project_id'), project_id),
    ai_metadata = COALESCE(sqlc.narg('ai_metadata'), ai_metadata),
    reading_time_min = COALESCE(sqlc.narg('reading_time_min'), reading_time_min),
    cover_image = COALESCE(sqlc.narg('cover_image'), cover_image),
    updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: PublishContent :one
-- Atomically sets status=published, is_public=true, and published_at.
-- Publishing always makes content publicly visible in this system.
UPDATE contents SET status = 'published', is_public = true, published_at = now(), updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: ArchiveContent :exec
UPDATE contents SET status = 'archived', updated_at = now() WHERE id = $1;

-- name: ArchiveContentReturning :one
-- Archive a content row and return the updated row. Used by the REST
-- archive endpoint which returns the row body; ArchiveContent (:exec) is
-- kept for DeleteContent's soft-delete path which discards the row.
UPDATE contents SET status = 'archived', updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: SubmitContentForReview :one
-- Transition content from draft to review. Returns pgx.ErrNoRows when the
-- row does not exist OR the current status is not 'draft' — the handler
-- translates "not found under this transition" into a 400 INVALID_STATE.
-- The WHERE-status guard makes the transition race-safe without a
-- separate read-then-write round trip.
UPDATE contents SET status = 'review', updated_at = now()
WHERE id = $1 AND status = 'draft'
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: RevertContentToDraft :one
-- Transition content from review back to draft (reviewer rejection path).
-- Same race-safe pattern as SubmitContentForReview; pgx.ErrNoRows means
-- "not in review state" which surfaces as 400 INVALID_STATE.
UPDATE contents SET status = 'draft', updated_at = now()
WHERE id = $1 AND status = 'review'
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: TopicsForContent :many
SELECT t.id, t.slug, t.name
FROM content_topics ct
JOIN topics t ON t.id = ct.topic_id
WHERE ct.content_id = $1;

-- name: TopicsForContents :many
SELECT ct.content_id, t.id, t.slug, t.name
FROM content_topics ct
JOIN topics t ON t.id = ct.topic_id
WHERE ct.content_id = ANY($1::uuid[]);

-- name: AddContentTopic :exec
INSERT INTO content_topics (content_id, topic_id) VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: DeleteContentTopics :exec
DELETE FROM content_topics WHERE content_id = $1;

-- name: TagsForContent :many
SELECT t.id, t.slug, t.name
FROM content_tags ct
JOIN tags t ON t.id = ct.tag_id
WHERE ct.content_id = $1;

-- name: TagsForContents :many
SELECT ct.content_id, t.id, t.slug, t.name
FROM content_tags ct
JOIN tags t ON t.id = ct.tag_id
WHERE ct.content_id = ANY($1::uuid[]);

-- name: DeleteContentTags :exec
DELETE FROM content_tags WHERE content_id = $1;

-- name: ContentEmbeddingBySlug :one
SELECT id, embedding FROM contents WHERE slug = $1 AND status = 'published' AND is_public = true;

-- name: SimilarContents :many
SELECT c.id, c.slug, c.title, c.excerpt, c.type,
       (1 - (c.embedding <=> @target_embedding::vector))::float8 AS similarity
FROM contents c
WHERE c.status = 'published' AND c.is_public = true
  AND c.id != @exclude_id
  AND c.embedding IS NOT NULL
ORDER BY c.embedding <=> @target_embedding::vector
LIMIT @max_results;

-- name: PublishedWithEmbeddings :many
SELECT id, slug, title, type, embedding
FROM contents
WHERE status = 'published' AND is_public = true
  AND embedding IS NOT NULL;

-- name: ContentsByStatus :many
-- List contents by status, ordered by updated_at descending. Used by admin pipeline.
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = @status::content_status
ORDER BY updated_at DESC
LIMIT @max_results;

-- name: ContentIDBySlug :one
-- Fetch existing content id for a given slug. Used to return structured conflict info
-- when CreateContent hits a unique violation on the slug index.
SELECT id FROM contents WHERE slug = $1;

-- name: AddContentConcept :exec
-- Link a content row to a concept (content_concepts junction). Relevance
-- defaults to 'primary'; caller passes 'secondary' for supporting concepts.
INSERT INTO content_concepts (content_id, concept_id, relevance)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING;

