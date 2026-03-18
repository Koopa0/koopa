-- name: Sources :many
-- List all registered Notion sources, newest first.
SELECT id, database_id, name, description, sync_mode, property_map,
       poll_interval, enabled, last_synced_at, created_at, updated_at
FROM notion_sources
ORDER BY created_at DESC;

-- name: SourceByID :one
-- Get a single Notion source by primary key.
SELECT id, database_id, name, description, sync_mode, property_map,
       poll_interval, enabled, last_synced_at, created_at, updated_at
FROM notion_sources WHERE id = $1;

-- name: CreateSource :one
-- Register a new Notion database source.
INSERT INTO notion_sources (database_id, name, description, sync_mode, property_map, poll_interval)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, database_id, name, description, sync_mode, property_map,
          poll_interval, enabled, last_synced_at, created_at, updated_at;

-- name: UpdateSource :one
-- Update a source's mutable fields. Only non-NULL args override.
UPDATE notion_sources SET
    name = COALESCE(sqlc.narg('name'), name),
    description = COALESCE(sqlc.narg('description'), description),
    sync_mode = COALESCE(sqlc.narg('sync_mode'), sync_mode),
    property_map = COALESCE(sqlc.narg('property_map'), property_map),
    poll_interval = COALESCE(sqlc.narg('poll_interval'), poll_interval),
    enabled = COALESCE(sqlc.narg('enabled'), enabled),
    updated_at = now()
WHERE id = @id
RETURNING id, database_id, name, description, sync_mode, property_map,
          poll_interval, enabled, last_synced_at, created_at, updated_at;

-- name: DeleteSource :execrows
-- Remove a Notion source registration. Returns rows affected.
DELETE FROM notion_sources WHERE id = $1;

-- name: ToggleSourceEnabled :one
-- Flip the enabled flag on a source.
UPDATE notion_sources SET
    enabled = NOT enabled,
    updated_at = now()
WHERE id = $1
RETURNING id, database_id, name, description, sync_mode, property_map,
          poll_interval, enabled, last_synced_at, created_at, updated_at;

-- name: UpdateSourceLastSynced :exec
-- Record a successful sync timestamp.
UPDATE notion_sources SET
    last_synced_at = now(),
    updated_at = now()
WHERE id = $1;
