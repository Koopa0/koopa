-- name: ContentByID :one
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents WHERE id = $1;

-- name: PublishedContents :many
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published'
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('tag')::text IS NULL OR sqlc.narg('tag') = ANY(tags))
ORDER BY published_at DESC NULLS LAST
LIMIT $1 OFFSET $2;

-- name: PublishedContentsCount :one
SELECT COUNT(*) FROM contents
WHERE status = 'published'
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('tag')::text IS NULL OR sqlc.narg('tag') = ANY(tags));

-- name: ContentBySlug :one
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents WHERE slug = $1;

-- name: ContentsByTopicID :many
SELECT c.id, c.slug, c.title, c.body, c.excerpt, c.type, c.status, c.tags,
       c.source, c.source_type, c.series_id, c.series_order, c.review_level,
       c.ai_metadata, c.reading_time, c.cover_image, c.published_at, c.created_at, c.updated_at
FROM contents c
JOIN content_topics ct ON ct.content_id = c.id
WHERE ct.topic_id = $1 AND c.status = 'published'
ORDER BY c.published_at DESC NULLS LAST
LIMIT $2 OFFSET $3;

-- name: ContentsByTopicIDCount :one
SELECT COUNT(*) FROM contents c
JOIN content_topics ct ON ct.content_id = c.id
WHERE ct.topic_id = $1 AND c.status = 'published';

-- name: SearchContents :many
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published'
  AND search_vector @@ websearch_to_tsquery('english', $1)
ORDER BY ts_rank(search_vector, websearch_to_tsquery('english', $1)) DESC
LIMIT $2 OFFSET $3;

-- name: SearchContentsCount :one
SELECT COUNT(*) FROM contents
WHERE status = 'published'
  AND search_vector @@ websearch_to_tsquery('english', $1);

-- name: PublishedForRSS :many
SELECT id, slug, title, excerpt, type, published_at, updated_at
FROM contents
WHERE status = 'published'
ORDER BY published_at DESC NULLS LAST
LIMIT $1;

-- name: AllPublishedSlugs :many
SELECT slug, type, updated_at
FROM contents
WHERE status = 'published'
ORDER BY updated_at DESC;

-- name: CreateContent :one
INSERT INTO contents (slug, title, body, excerpt, type, status, tags, source, source_type,
                      series_id, series_order, review_level, ai_metadata, reading_time, cover_image)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
RETURNING id, slug, title, body, excerpt, type, status, tags, source, source_type,
          series_id, series_order, review_level, ai_metadata, reading_time,
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
    ai_metadata = COALESCE(sqlc.narg('ai_metadata'), ai_metadata),
    reading_time = COALESCE(sqlc.narg('reading_time'), reading_time),
    cover_image = COALESCE(sqlc.narg('cover_image'), cover_image),
    updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status, tags, source, source_type,
          series_id, series_order, review_level, ai_metadata, reading_time,
          cover_image, published_at, created_at, updated_at;

-- name: PublishContent :one
UPDATE contents SET status = 'published', published_at = now(), updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status, tags, source, source_type,
          series_id, series_order, review_level, ai_metadata, reading_time,
          cover_image, published_at, created_at, updated_at;

-- name: ArchiveContent :exec
UPDATE contents SET status = 'archived', updated_at = now() WHERE id = $1;

-- name: UpdateContentEmbedding :exec
UPDATE contents SET embedding = $2 WHERE id = $1;

-- name: PublishedContentsByDateRange :many
SELECT id, slug, title, body, excerpt, type, status, tags, source, source_type,
       series_id, series_order, review_level, ai_metadata, reading_time,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published' AND published_at >= $1 AND published_at < $2
ORDER BY published_at DESC;

-- name: PublishedContentCountSince :one
SELECT count(*) FROM contents
WHERE status = 'published' AND published_at >= $1;

-- name: TopicsForContent :many
SELECT t.id, t.slug, t.name FROM topics t
JOIN content_topics ct ON ct.topic_id = t.id
WHERE ct.content_id = $1;

-- name: AddContentTopic :exec
INSERT INTO content_topics (content_id, topic_id) VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: SetContentTopics :exec
DELETE FROM content_topics WHERE content_id = $1;

-- name: ObsidianContentSlugs :many
SELECT slug FROM contents WHERE source_type = 'obsidian' ORDER BY slug;

-- name: ContentEmbeddingBySlug :one
SELECT id, embedding FROM contents WHERE slug = $1 AND status = 'published';

-- name: SimilarContents :many
SELECT c.id, c.slug, c.title, c.excerpt, c.type,
       (1 - (c.embedding <=> @target_embedding::vector))::float8 AS similarity
FROM contents c
WHERE c.status = 'published'
  AND c.id != @exclude_id
  AND c.embedding IS NOT NULL
ORDER BY c.embedding <=> @target_embedding::vector
LIMIT @max_results;

-- name: PublishedWithEmbeddings :many
SELECT id, slug, title, type, embedding
FROM contents
WHERE status = 'published' AND embedding IS NOT NULL;
