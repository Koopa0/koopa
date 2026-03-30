-- name: ContentByID :one
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, visibility, project_id, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents WHERE id = $1;

-- name: PublishedContents :many
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, visibility, project_id, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published' AND visibility = 'public'
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('tag')::text IS NULL OR sqlc.narg('tag') = ANY(tags))
  AND (sqlc.narg('since')::timestamptz IS NULL OR published_at >= sqlc.narg('since'))
ORDER BY published_at DESC NULLS LAST
LIMIT $1 OFFSET $2;

-- name: PublishedContentsCount :one
SELECT COUNT(*) FROM contents
WHERE status = 'published' AND visibility = 'public'
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('tag')::text IS NULL OR sqlc.narg('tag') = ANY(tags))
  AND (sqlc.narg('since')::timestamptz IS NULL OR published_at >= sqlc.narg('since'));

-- name: ContentBySlug :one
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, visibility, project_id, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents WHERE slug = $1;

-- name: ContentsByTopicID :many
SELECT c.id, c.slug, c.title, c.body, c.excerpt, c.type, c.status, c.tags,
       c.source, c.source_type, c.series_id, c.series_order, c.review_level,
       c.visibility, c.project_id, c.ai_metadata, c.reading_time, c.cover_image,
       c.published_at, c.created_at, c.updated_at
FROM contents c
JOIN content_topics ct ON ct.content_id = c.id
WHERE ct.topic_id = $1 AND c.status = 'published' AND c.visibility = 'public'
ORDER BY c.published_at DESC NULLS LAST
LIMIT $2 OFFSET $3;

-- name: ContentsByTopicIDCount :one
SELECT COUNT(*) FROM contents c
JOIN content_topics ct ON ct.content_id = c.id
WHERE ct.topic_id = $1 AND c.status = 'published' AND c.visibility = 'public';

-- name: SearchContents :many
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, visibility, project_id, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published' AND visibility = 'public'
  AND search_vector @@ websearch_to_tsquery('simple', $1)
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
ORDER BY ts_rank(search_vector, websearch_to_tsquery('simple', $1)) DESC
LIMIT $2 OFFSET $3;

-- name: SearchContentsCount :one
SELECT COUNT(*) FROM contents
WHERE status = 'published' AND visibility = 'public'
  AND search_vector @@ websearch_to_tsquery('simple', $1)
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'));

-- name: SearchContentsOR :many
-- Fallback search using OR semantics: splits query into words and matches any.
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, visibility, project_id, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published' AND visibility = 'public'
  AND search_vector @@ to_tsquery('simple', replace(plainto_tsquery('simple', $1)::text, '&', '|'))
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
ORDER BY ts_rank(search_vector, to_tsquery('simple', replace(plainto_tsquery('simple', $1)::text, '&', '|'))) DESC
LIMIT $2 OFFSET $3;

-- name: InternalSearchContents :many
-- Internal search without visibility filter (for MCP tools).
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, visibility, project_id, ai_metadata, reading_time,
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
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, visibility, project_id, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published'
  AND search_vector @@ to_tsquery('simple', replace(plainto_tsquery('simple', $1)::text, '&', '|'))
ORDER BY ts_rank(search_vector, to_tsquery('simple', replace(plainto_tsquery('simple', $1)::text, '&', '|'))) DESC
LIMIT $2 OFFSET $3;

-- name: PublishedForRSS :many
SELECT id, slug, title, excerpt, type, published_at, updated_at
FROM contents
WHERE status = 'published' AND visibility = 'public'
ORDER BY published_at DESC NULLS LAST
LIMIT $1;

-- name: AdminListContents :many
-- Admin list: all statuses, all visibilities, with optional type and visibility filter.
SELECT id, slug, title, excerpt, type, status, visibility, project_id, tags,
       reading_time, published_at, created_at, updated_at
FROM contents
WHERE (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('visibility')::text IS NULL OR visibility = sqlc.narg('visibility'))
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: AdminListContentsCount :one
SELECT COUNT(*) FROM contents
WHERE (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('visibility')::text IS NULL OR visibility = sqlc.narg('visibility'));

-- name: AllPublishedSlugs :many
SELECT slug, type, updated_at
FROM contents
WHERE status = 'published' AND visibility = 'public'
ORDER BY updated_at DESC;

-- name: CreateContent :one
INSERT INTO contents (slug, title, body, excerpt, type, status, tags, source, source_type,
                      series_id, series_order, review_level, visibility, project_id, ai_metadata,
                      reading_time, cover_image, search_text)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
        $16, $17, left($3, 10000))
RETURNING id, slug, title, body, excerpt, type, status, tags, source, source_type,
          series_id, series_order, review_level, visibility, project_id, ai_metadata, reading_time,
          cover_image, published_at, created_at, updated_at;

-- name: UpdateContent :one
UPDATE contents SET
    slug = COALESCE(sqlc.narg('slug'), slug),
    title = COALESCE(sqlc.narg('title'), title),
    body = COALESCE(sqlc.narg('body'), body),
    excerpt = COALESCE(sqlc.narg('excerpt'), excerpt),
    type = COALESCE(sqlc.narg('content_type')::content_type, type),
    status = COALESCE(sqlc.narg('status')::content_status, status),
    tags = COALESCE(sqlc.narg('tags'), tags),
    source = COALESCE(sqlc.narg('source'), source),
    source_type = COALESCE(sqlc.narg('source_type')::source_type, source_type),
    series_id = COALESCE(sqlc.narg('series_id'), series_id),
    series_order = COALESCE(sqlc.narg('series_order'), series_order),
    review_level = COALESCE(sqlc.narg('review_level')::review_level, review_level),
    visibility = COALESCE(sqlc.narg('visibility'), visibility),
    project_id = COALESCE(sqlc.narg('project_id'), project_id),
    ai_metadata = COALESCE(sqlc.narg('ai_metadata'), ai_metadata),
    reading_time = COALESCE(sqlc.narg('reading_time'), reading_time),
    cover_image = COALESCE(sqlc.narg('cover_image'), cover_image),
    search_text = left(COALESCE(sqlc.narg('body'), body), 10000),
    updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status, tags, source, source_type,
          series_id, series_order, review_level, visibility, project_id, ai_metadata, reading_time,
          cover_image, published_at, created_at, updated_at;

-- name: PublishContent :one
UPDATE contents SET status = 'published', published_at = now(), updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status, tags, source, source_type,
          series_id, series_order, review_level, visibility, project_id, ai_metadata, reading_time,
          cover_image, published_at, created_at, updated_at;

-- name: ArchiveContent :exec
UPDATE contents SET status = 'archived', updated_at = now() WHERE id = $1;

-- name: UpdateContentEmbedding :exec
UPDATE contents SET embedding = $2 WHERE id = $1;

-- name: PublishedContentsByDateRange :many
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, visibility, project_id, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published' AND visibility = 'public'
  AND published_at >= $1 AND published_at < $2
ORDER BY published_at DESC;

-- name: PublishedContentCountSince :one
SELECT count(*) FROM contents
WHERE status = 'published' AND visibility = 'public'
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

-- name: ObsidianContentSlugs :many
SELECT slug FROM contents WHERE source_type = 'obsidian' ORDER BY slug;

-- name: ContentEmbeddingBySlug :one
SELECT id, embedding FROM contents WHERE slug = $1 AND status = 'published' AND visibility = 'public';

-- name: SimilarContents :many
SELECT c.id, c.slug, c.title, c.excerpt, c.type,
       (1 - (c.embedding <=> @target_embedding::vector))::float8 AS similarity
FROM contents c
WHERE c.status = 'published' AND c.visibility = 'public'
  AND c.id != @exclude_id
  AND c.embedding IS NOT NULL
ORDER BY c.embedding <=> @target_embedding::vector
LIMIT @max_results;

-- name: PublishedWithEmbeddings :many
SELECT id, slug, title, type, embedding
FROM contents
WHERE status = 'published' AND visibility = 'public'
  AND embedding IS NOT NULL;

-- name: RecentContentsByType :many
-- Get recent contents of a specific type, ordered by creation date.
-- Internal use (MCP) — no visibility filter.
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, visibility, project_id, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE type = @content_type::content_type
  AND created_at >= @since
ORDER BY created_at DESC
LIMIT @max_results;

-- name: ContentTagsByTypeAndProject :many
-- Fetch id, tags, and created_at for learning analytics aggregation.
-- Used by MCP get_tag_summary, get_coverage_matrix, get_weakness_trend.
SELECT id, tags, created_at
FROM contents
WHERE type = @content_type::content_type
  AND (sqlc.narg('project_id')::uuid IS NULL OR project_id = sqlc.narg('project_id'))
  AND created_at >= @since
ORDER BY created_at DESC;

-- name: ContentRichTagEntries :many
-- Fetch id, slug, title, tags, ai_metadata, and created_at for learning analytics
-- that need structured metadata (weakness trend, learning timeline).
-- Heavier than ContentTagsByTypeAndProject — only use when slug/title/metadata are needed.
SELECT id, slug, title, tags, ai_metadata, created_at
FROM contents
WHERE type = @content_type::content_type
  AND (sqlc.narg('project_id')::uuid IS NULL OR project_id = sqlc.narg('project_id'))
  AND created_at >= @since
ORDER BY created_at DESC;
