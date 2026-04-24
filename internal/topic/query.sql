-- name: Topics :many
SELECT t.id, t.slug, t.name, t.description, t.icon, t.sort_order, t.created_at, t.updated_at,
       COUNT(ct.content_id) FILTER (WHERE c.status = 'published') AS content_count
FROM topics t
LEFT JOIN content_topics ct ON ct.topic_id = t.id
LEFT JOIN contents c ON c.id = ct.content_id
GROUP BY t.id
ORDER BY t.sort_order, t.name;

-- name: TopicBySlug :one
SELECT t.id, t.slug, t.name, t.description, t.icon, t.sort_order, t.created_at, t.updated_at,
       COUNT(ct.content_id) FILTER (WHERE c.status = 'published') AS content_count
FROM topics t
LEFT JOIN content_topics ct ON ct.topic_id = t.id
LEFT JOIN contents c ON c.id = ct.content_id
WHERE t.slug = $1
GROUP BY t.id;

-- name: AllTopicSlugs :many
SELECT slug, name FROM topics ORDER BY name;

-- name: CreateTopic :one
INSERT INTO topics (slug, name, description, icon, sort_order)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, slug, name, description, icon, sort_order, created_at, updated_at;

-- name: UpdateTopic :one
UPDATE topics SET
    slug = COALESCE(sqlc.narg('slug'), slug),
    name = COALESCE(sqlc.narg('name'), name),
    description = COALESCE(sqlc.narg('description'), description),
    icon = COALESCE(sqlc.narg('icon'), icon),
    sort_order = COALESCE(sqlc.narg('sort_order'), sort_order),
    updated_at = now()
WHERE id = $1
RETURNING id, slug, name, description, icon, sort_order, created_at, updated_at;

-- name: RelatedTagsForTopic :many
SELECT tg.slug AS tag, COUNT(*)::int AS count
FROM contents c
JOIN content_topics ct ON ct.content_id = c.id
JOIN content_tags ct2 ON ct2.content_id = c.id
JOIN tags tg ON tg.id = ct2.tag_id
WHERE ct.topic_id = $1
  AND c.status = 'published'
  AND c.is_public = true
GROUP BY tg.slug
ORDER BY count DESC
LIMIT $2;

-- name: DeleteTopic :exec
DELETE FROM topics WHERE id = $1;
