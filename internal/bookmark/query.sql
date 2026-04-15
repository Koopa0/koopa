-- Queries for the bookmark package. See migrations/005_bookmarks_schema.up.sql
-- for the table definition. url_hash / slug uniqueness is enforced by
-- constraints; callers rely on pgerrcode 23505 → ErrConflict mapping.

-- name: CreateBookmark :one
INSERT INTO bookmarks (
    url, url_hash, slug, title, excerpt, note,
    source_type, source_feed_entry_id,
    curated_by, is_public, published_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8,
    $9, $10, $11
)
RETURNING id, url, url_hash, slug, title, excerpt, note,
          source_type, source_feed_entry_id,
          curated_by, curated_at, is_public, published_at,
          created_at, updated_at;

-- name: BookmarkByID :one
SELECT id, url, url_hash, slug, title, excerpt, note,
       source_type, source_feed_entry_id,
       curated_by, curated_at, is_public, published_at,
       created_at, updated_at
FROM bookmarks
WHERE id = $1;

-- name: BookmarkBySlug :one
SELECT id, url, url_hash, slug, title, excerpt, note,
       source_type, source_feed_entry_id,
       curated_by, curated_at, is_public, published_at,
       created_at, updated_at
FROM bookmarks
WHERE slug = $1 AND is_public = true;

-- name: PublicBookmarks :many
SELECT id, url, url_hash, slug, title, excerpt, note,
       source_type, source_feed_entry_id,
       curated_by, curated_at, is_public, published_at,
       created_at, updated_at
FROM bookmarks
WHERE is_public = true
  AND (sqlc.narg('since')::timestamptz IS NULL OR curated_at >= sqlc.narg('since'))
ORDER BY curated_at DESC
LIMIT $1 OFFSET $2;

-- name: PublicBookmarksCount :one
SELECT COUNT(*) FROM bookmarks
WHERE is_public = true
  AND (sqlc.narg('since')::timestamptz IS NULL OR curated_at >= sqlc.narg('since'));

-- name: AdminBookmarks :many
SELECT id, url, url_hash, slug, title, excerpt, note,
       source_type, source_feed_entry_id,
       curated_by, curated_at, is_public, published_at,
       created_at, updated_at
FROM bookmarks
WHERE (sqlc.narg('is_public')::boolean IS NULL OR is_public = sqlc.narg('is_public'))
ORDER BY curated_at DESC
LIMIT $1 OFFSET $2;

-- name: AdminBookmarksCount :one
SELECT COUNT(*) FROM bookmarks
WHERE (sqlc.narg('is_public')::boolean IS NULL OR is_public = sqlc.narg('is_public'));

-- name: DeleteBookmark :execrows
DELETE FROM bookmarks WHERE id = $1;

-- name: TopicsForBookmark :many
SELECT t.id, t.slug, t.name
FROM bookmark_topics bt
JOIN topics t ON t.id = bt.topic_id
WHERE bt.bookmark_id = $1;

-- name: TopicsForBookmarks :many
SELECT bt.bookmark_id, t.id, t.slug, t.name
FROM bookmark_topics bt
JOIN topics t ON t.id = bt.topic_id
WHERE bt.bookmark_id = ANY($1::uuid[]);

-- name: AddBookmarkTopic :exec
INSERT INTO bookmark_topics (bookmark_id, topic_id) VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: DeleteBookmarkTopics :exec
DELETE FROM bookmark_topics WHERE bookmark_id = $1;

-- name: TagsForBookmark :many
SELECT t.name
FROM bookmark_tags bt
JOIN tags t ON t.id = bt.tag_id
WHERE bt.bookmark_id = $1
ORDER BY t.name;

-- name: TagsForBookmarks :many
SELECT bt.bookmark_id, t.name
FROM bookmark_tags bt
JOIN tags t ON t.id = bt.tag_id
WHERE bt.bookmark_id = ANY($1::uuid[])
ORDER BY bt.bookmark_id, t.name;
