-- name: AliasesByExactRawTags :many
-- Batch resolve: find all exact alias matches for a list of raw tags.
SELECT * FROM tag_aliases WHERE raw_tag = ANY(@raw_tags::text[]) AND tag_id IS NOT NULL;

-- name: AliasByExactRawTag :one
-- Step 1: exact match on raw_tag with a mapped tag_id.
SELECT * FROM tag_aliases WHERE raw_tag = $1 AND tag_id IS NOT NULL;

-- name: IsAliasRejected :one
-- Check if a raw_tag has been explicitly rejected by admin.
SELECT EXISTS(SELECT 1 FROM tag_aliases WHERE raw_tag = $1 AND match_method = 'rejected') AS rejected;

-- name: AliasByCaseInsensitiveRawTag :one
-- Step 2: case-insensitive match on raw_tag with a mapped tag_id.
SELECT * FROM tag_aliases WHERE LOWER(raw_tag) = LOWER(sqlc.arg(raw_tag)) AND tag_id IS NOT NULL
LIMIT 1;

-- name: TagBySlug :one
-- Step 3: match canonical tag by slug.
SELECT * FROM tags WHERE slug = $1;

-- name: InsertUnmappedAlias :exec
-- Step 4: record unmapped raw tag for admin review.
INSERT INTO tag_aliases (raw_tag, tag_id, match_method, confirmed)
VALUES ($1, NULL, 'unmapped', false)
ON CONFLICT (raw_tag) DO NOTHING;

-- name: InsertAliasWithTag :exec
-- Record a resolved alias mapping (steps 2-3 auto-create alias for future exact match).
INSERT INTO tag_aliases (raw_tag, tag_id, match_method, confirmed)
VALUES ($1, $2, $3, false)
ON CONFLICT (raw_tag) DO NOTHING;

-- name: DeleteNoteTagsByObsidianNoteID :exec
DELETE FROM obsidian_note_tags WHERE obsidian_note_id = $1;

-- name: InsertNoteTag :exec
INSERT INTO obsidian_note_tags (obsidian_note_id, tag_id)
VALUES ($1, $2)
ON CONFLICT (obsidian_note_id, tag_id) DO NOTHING;

-- name: InsertNoteTags :exec
INSERT INTO obsidian_note_tags (obsidian_note_id, tag_id)
SELECT @obsidian_note_id, unnest(@tag_ids::uuid[])
ON CONFLICT DO NOTHING;

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

-- Admin: count note-tag junctions referencing a tag.
-- name: NoteTagCountByTagID :one
SELECT COUNT(*)::int AS count FROM obsidian_note_tags WHERE tag_id = $1;

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
    match_method = 'manual',
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

-- Admin: reject an alias — set tag_id to NULL and match_method to 'rejected'.
-- name: RejectAlias :one
UPDATE tag_aliases SET
    tag_id = NULL,
    match_method = 'rejected',
    confirmed = false,
    confirmed_at = NULL
WHERE id = $1
RETURNING *;

-- Admin: delete an alias.
-- name: DeleteAlias :exec
DELETE FROM tag_aliases WHERE id = $1;

-- Backfill: list obsidian_notes that have raw tags in JSONB.
-- name: NotesWithRawTags :many
SELECT id, raw_tags FROM obsidian_notes
WHERE raw_tags IS NOT NULL AND raw_tags::text != 'null' AND raw_tags::text != '[]'
ORDER BY id;

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

-- Merge: delete duplicate note-tags before reassignment.
-- name: DeleteDuplicateNoteTags :execrows
-- $1 = source_id, $2 = target_id
DELETE FROM obsidian_note_tags
WHERE obsidian_note_tags.tag_id = $1
  AND obsidian_note_tags.obsidian_note_id IN (SELECT ont.obsidian_note_id FROM obsidian_note_tags ont WHERE ont.tag_id = $2);

-- Merge: reassign remaining note-tags from source to target.
-- name: ReassignNoteTags :execrows
-- $1 = target_id, $2 = source_id
UPDATE obsidian_note_tags SET tag_id = $1 WHERE obsidian_note_tags.tag_id = $2;

-- Merge: delete duplicate event-tags before reassignment.
-- name: DeleteDuplicateEventTags :execrows
-- $1 = source_id, $2 = target_id
DELETE FROM event_tags
WHERE event_tags.tag_id = $1
  AND event_tags.event_id IN (SELECT aet.event_id FROM event_tags aet WHERE aet.tag_id = $2);

-- Merge: reassign remaining event-tags from source to target.
-- name: ReassignEventTags :execrows
-- $1 = target_id, $2 = source_id
UPDATE event_tags SET tag_id = $1 WHERE event_tags.tag_id = $2;
