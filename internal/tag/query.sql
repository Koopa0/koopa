-- name: AliasesByExactRawTags :many
-- Batch resolve: find all exact alias matches for a list of raw tags.
SELECT * FROM tag_aliases WHERE raw_tag = ANY(@raw_tags::text[]) AND tag_id IS NOT NULL;

-- name: AliasByExactRawTag :one
-- Step 1: exact match on raw_tag with a mapped tag_id.
SELECT * FROM tag_aliases WHERE raw_tag = $1 AND tag_id IS NOT NULL;

-- name: IsAliasRejected :one
-- Check if a raw_tag has been explicitly rejected by admin.
SELECT EXISTS(SELECT 1 FROM tag_aliases WHERE raw_tag = $1 AND resolution_source = 'rejected') AS rejected;

-- name: AliasByCaseInsensitiveRawTag :one
-- Step 2: case-insensitive match on raw_tag with a mapped tag_id.
SELECT * FROM tag_aliases WHERE LOWER(raw_tag) = LOWER(sqlc.arg(raw_tag)) AND tag_id IS NOT NULL
LIMIT 1;

-- name: TagBySlug :one
-- Step 3: match canonical tag by slug.
SELECT * FROM tags WHERE slug = $1;

-- name: InsertUnmappedAlias :exec
-- Step 4: record unmapped raw tag for admin review.
INSERT INTO tag_aliases (raw_tag, tag_id, resolution_source, confirmed)
VALUES ($1, NULL, 'unmapped', false)
ON CONFLICT (raw_tag) DO NOTHING;

-- name: InsertAliasWithTag :exec
-- Record a resolved alias mapping (steps 2-3 auto-create alias for future exact match).
INSERT INTO tag_aliases (raw_tag, tag_id, resolution_source, confirmed)
VALUES ($1, $2, $3, false)
ON CONFLICT (raw_tag) DO NOTHING;

-- Admin: list all canonical tags ordered by name.
-- name: ListTags :many
SELECT * FROM tags ORDER BY name;

-- Admin: get a single tag by ID.
-- name: TagByID :one
SELECT * FROM tags WHERE id = $1;

-- Admin: create a canonical tag.
-- name: CreateTag :one
INSERT INTO tags (slug, name, parent_id, description)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- Admin: update a canonical tag.
-- name: UpdateTag :one
UPDATE tags SET
    slug = COALESCE(sqlc.narg(slug), slug),
    name = COALESCE(sqlc.narg(name), name),
    parent_id = sqlc.narg(parent_id),
    description = COALESCE(sqlc.narg(description), description),
    updated_at = now()
WHERE id = $1
RETURNING *;

-- Admin: delete a canonical tag (only if no aliases reference it).
-- name: DeleteTag :exec
DELETE FROM tags WHERE id = $1;

-- Admin: count aliases referencing a tag.
-- name: AliasCountByTagID :one
SELECT COUNT(*)::int AS count FROM tag_aliases WHERE tag_id = $1;

-- Admin: list aliases with optional unmapped filter.
-- name: ListAliases :many
SELECT * FROM tag_aliases ORDER BY created_at DESC;

-- Admin: list only unmapped aliases (tag_id IS NULL).
-- name: ListUnmappedAliases :many
SELECT * FROM tag_aliases WHERE tag_id IS NULL ORDER BY created_at DESC;

-- Admin: map an alias to a canonical tag.
-- name: MapAlias :one
UPDATE tag_aliases SET
    tag_id = $2,
    resolution_source = 'admin',
    confirmed = true,
    confirmed_at = now()
WHERE id = $1
RETURNING *;

-- Admin: confirm an alias mapping.
-- name: ConfirmAlias :one
UPDATE tag_aliases SET
    confirmed = true,
    confirmed_at = now()
WHERE id = $1
RETURNING *;

-- Admin: reject an alias — set tag_id to NULL and resolution_source to 'rejected'.
-- name: RejectAlias :one
UPDATE tag_aliases SET
    tag_id = NULL,
    resolution_source = 'rejected',
    confirmed = false,
    confirmed_at = NULL
WHERE id = $1
RETURNING *;

-- Admin: delete an alias.
-- name: DeleteAlias :exec
DELETE FROM tag_aliases WHERE id = $1;

-- Merge: delete duplicate aliases before reassignment (source aliases whose raw_tag already exists under target).
-- name: DeleteDuplicateAliases :execrows
-- $1 = source_id, $2 = target_id
DELETE FROM tag_aliases
WHERE tag_aliases.tag_id = $1
  AND tag_aliases.raw_tag IN (SELECT ta.raw_tag FROM tag_aliases ta WHERE ta.tag_id = $2);

-- Merge: reassign remaining aliases from source to target.
-- name: ReassignAliases :execrows
-- $1 = target_id, $2 = source_id
UPDATE tag_aliases SET tag_id = $1 WHERE tag_aliases.tag_id = $2;

-- Merge: delete duplicate content tags (source already attached to same content as target).
-- name: DeleteDuplicateContentTags :execrows
-- $1 = source_id, $2 = target_id
DELETE FROM content_tags
WHERE content_tags.tag_id = $1
  AND content_tags.content_id IN (SELECT ct.content_id FROM content_tags ct WHERE ct.tag_id = $2);

-- Merge: reassign remaining content tags from source to target.
-- name: ReassignContentTags :execrows
-- $1 = target_id, $2 = source_id
UPDATE content_tags SET tag_id = $1 WHERE content_tags.tag_id = $2;

-- Merge: delete duplicate bookmark tags (source already attached to same bookmark as target).
-- name: DeleteDuplicateBookmarkTags :execrows
-- $1 = source_id, $2 = target_id
DELETE FROM bookmark_tags
WHERE bookmark_tags.tag_id = $1
  AND bookmark_tags.bookmark_id IN (SELECT bt.bookmark_id FROM bookmark_tags bt WHERE bt.tag_id = $2);

-- Merge: reassign remaining bookmark tags from source to target.
-- name: ReassignBookmarkTags :execrows
-- $1 = target_id, $2 = source_id
UPDATE bookmark_tags SET tag_id = $1 WHERE bookmark_tags.tag_id = $2;

