-- name: ContentByID :one
SELECT id, slug, title, body, excerpt, type, status, source, source_type,
       series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents WHERE id = $1;

-- name: PublishedContents :many
SELECT id, slug, title, body, excerpt, type, status, source, source_type,
       series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
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
SELECT id, slug, title, body, excerpt, type, status, source, source_type,
       series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents WHERE slug = $1;

-- name: ContentsByTopicID :many
SELECT c.id, c.slug, c.title, c.body, c.excerpt, c.type, c.status,
       c.source, c.source_type, c.series_id, c.series_order, c.review_level,
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
SELECT id, slug, title, body, excerpt, type, status, source, source_type,
       series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
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

-- name: SearchContentsOR :many
-- Fallback search using OR semantics: splits query into words and matches any.
SELECT id, slug, title, body, excerpt, type, status, source, source_type,
       series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
  AND search_vector @@ to_tsquery('simple', replace(plainto_tsquery('simple', $1)::text, '&', '|'))
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
ORDER BY ts_rank(search_vector, to_tsquery('simple', replace(plainto_tsquery('simple', $1)::text, '&', '|'))) DESC
LIMIT $2 OFFSET $3;

-- name: SearchContentsORCount :one
SELECT COUNT(*) FROM contents
WHERE status = 'published' AND is_public = true
  AND search_vector @@ to_tsquery('simple', replace(plainto_tsquery('simple', $1)::text, '&', '|'))
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'));

-- name: InternalSearchContents :many
-- Internal search without visibility filter (for MCP tools).
SELECT id, slug, title, body, excerpt, type, status, source, source_type,
       series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published'
  AND search_vector @@ websearch_to_tsquery('simple', $1)
ORDER BY ts_rank(search_vector, websearch_to_tsquery('simple', $1)) DESC
LIMIT $2 OFFSET $3;

-- name: InternalSearchContentsCount :one
SELECT COUNT(*) FROM contents
WHERE status = 'published'
  AND search_vector @@ websearch_to_tsquery('simple', $1);

-- name: InternalSearchContentsOR :many
-- Internal OR search without visibility filter (for MCP tools).
SELECT id, slug, title, body, excerpt, type, status, source, source_type,
       series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published'
  AND search_vector @@ to_tsquery('simple', replace(plainto_tsquery('simple', $1)::text, '&', '|'))
ORDER BY ts_rank(search_vector, to_tsquery('simple', replace(plainto_tsquery('simple', $1)::text, '&', '|'))) DESC
LIMIT $2 OFFSET $3;

-- name: PublishedForRSS :many
SELECT id, slug, title, excerpt, type, published_at, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
ORDER BY published_at DESC NULLS LAST
LIMIT $1;

-- name: AdminListContents :many
-- Admin list: all statuses, with optional type and is_public filter.
SELECT id, slug, title, excerpt, type, status, is_public, project_id,
       reading_time_min, published_at, created_at, updated_at
FROM contents
WHERE (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('is_public')::bool IS NULL OR is_public = sqlc.narg('is_public'))
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: AdminListContentsCount :one
SELECT COUNT(*) FROM contents
WHERE (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('is_public')::bool IS NULL OR is_public = sqlc.narg('is_public'));

-- name: AllPublishedSlugs :many
SELECT slug, type, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
ORDER BY updated_at DESC;

-- name: CreateContent :one
INSERT INTO contents (slug, title, body, excerpt, type, status, source, source_type,
                      series_id, series_order, review_level, is_public, project_id, ai_metadata,
                      reading_time_min, cover_image)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
        $15, $16)
RETURNING id, slug, title, body, excerpt, type, status, source, source_type,
          series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: UpdateContent :one
UPDATE contents SET
    slug = COALESCE(sqlc.narg('slug'), slug),
    title = COALESCE(sqlc.narg('title'), title),
    body = COALESCE(sqlc.narg('body'), body),
    excerpt = COALESCE(sqlc.narg('excerpt'), excerpt),
    type = COALESCE(sqlc.narg('content_type')::content_type, type),
    status = COALESCE(sqlc.narg('status')::content_status, status),
    source = COALESCE(sqlc.narg('source'), source),
    source_type = COALESCE(sqlc.narg('source_type')::source_type, source_type),
    series_id = COALESCE(sqlc.narg('series_id'), series_id),
    series_order = COALESCE(sqlc.narg('series_order'), series_order),
    review_level = COALESCE(sqlc.narg('review_level')::review_level, review_level),
    is_public = COALESCE(sqlc.narg('is_public'), is_public),
    project_id = COALESCE(sqlc.narg('project_id'), project_id),
    ai_metadata = COALESCE(sqlc.narg('ai_metadata'), ai_metadata),
    reading_time_min = COALESCE(sqlc.narg('reading_time_min'), reading_time_min),
    cover_image = COALESCE(sqlc.narg('cover_image'), cover_image),
    updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status, source, source_type,
          series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: PublishContent :one
UPDATE contents SET status = 'published', published_at = now(), updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status, source, source_type,
          series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: ArchiveContent :exec
UPDATE contents SET status = 'archived', updated_at = now() WHERE id = $1;

-- name: UpdateContentEmbedding :exec
UPDATE contents SET embedding = $2 WHERE id = $1;

-- name: PublishedContentsByDateRange :many
SELECT id, slug, title, body, excerpt, type, status, source, source_type,
       series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
  AND published_at >= $1 AND published_at < $2
ORDER BY published_at DESC
LIMIT $3;

-- name: PublishedContentCountSince :one
SELECT count(*) FROM contents
WHERE status = 'published' AND is_public = true
  AND published_at >= $1;

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

-- name: AddContentTag :exec
INSERT INTO content_tags (content_id, tag_id) VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: DeleteContentTags :exec
DELETE FROM content_tags WHERE content_id = $1;

-- name: ObsidianContentSlugs :many
SELECT slug FROM contents WHERE source_type = 'obsidian' ORDER BY slug;

-- name: ContentEmbeddingBySlug :one
SELECT id, embedding FROM contents WHERE slug = $1 AND status = 'published' AND is_public = true;

-- name: ContentEmbeddingBySlugAny :one
-- Like ContentEmbeddingBySlug but without visibility filter (for private TILs).
SELECT id, embedding FROM contents WHERE slug = $1 AND embedding IS NOT NULL;

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

-- name: RecentContentsByType :many
-- Get recent contents of a specific type, ordered by creation date.
-- Internal use (MCP) — no visibility filter.
SELECT id, slug, title, body, excerpt, type, status, source, source_type,
       series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE type = @content_type::content_type
  AND created_at >= @since
ORDER BY created_at DESC
LIMIT @max_results;

-- name: ContentRichTagEntries :many
-- Fetch id, slug, title, ai_metadata, project slug, and created_at for learning
-- analytics that need structured metadata (weakness trend, learning timeline).
SELECT c.id, c.slug, c.title, c.ai_metadata, c.created_at,
       p.slug AS project_slug
FROM contents c
LEFT JOIN projects p ON p.id = c.project_id
WHERE c.type = @content_type::content_type
  AND (sqlc.narg('project_id')::uuid IS NULL OR c.project_id = sqlc.narg('project_id'))
  AND c.created_at >= @since
ORDER BY c.created_at DESC;

-- name: SimilarTILs :many
-- Embedding-based similarity search across all TILs (including private).
-- No visibility filter — TILs are private by default.
SELECT c.id, c.slug, c.title, c.excerpt, c.type,
       (1 - (c.embedding <=> @target_embedding::vector))::float8 AS similarity
FROM contents c
WHERE c.type = 'til'
  AND c.id != @exclude_id
  AND c.embedding IS NOT NULL
ORDER BY c.embedding <=> @target_embedding::vector
LIMIT @max_results;

-- name: ContentsByStatus :many
-- List contents by status, ordered by updated_at descending. Used by admin pipeline.
SELECT id, slug, title, body, excerpt, type, status, source, source_type,
       series_id, series_order, review_level, is_public, project_id, ai_metadata, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = @status::content_status
ORDER BY updated_at DESC
LIMIT @max_results;

-- name: ContentsWithoutEmbedding :many
-- Contents that need embedding generation (TILs, articles, notes).
SELECT id, slug, title, body FROM contents
WHERE embedding IS NULL
  AND type IN ('til', 'article', 'note')
  AND body != ''
ORDER BY created_at DESC
LIMIT @lim;
