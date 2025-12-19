-- Artifact queries for sqlc
-- Table: artifact (renamed from session_artifacts in migration 000006)
-- Added: filename column (migration 000007)

-- name: SaveArtifact :one
-- UPSERT artifact by (session_id, filename)
-- If exists, updates content and increments version
INSERT INTO artifact (
    session_id,
    message_id,
    filename,
    type,
    language,
    title,
    content,
    version,
    sequence_number
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, 1,
    COALESCE((SELECT MAX(sequence_number) FROM artifact WHERE session_id = $1), 0) + 1
)
ON CONFLICT (session_id, filename) DO UPDATE SET
    message_id = EXCLUDED.message_id,
    type = EXCLUDED.type,
    language = EXCLUDED.language,
    title = EXCLUDED.title,
    content = EXCLUDED.content,
    version = artifact.version + 1,
    updated_at = NOW()
RETURNING *;

-- name: GetArtifactByFilename :one
-- Get artifact by session and filename
SELECT *
FROM artifact
WHERE session_id = $1 AND filename = $2;

-- name: ListArtifactFilenames :many
-- List all artifact filenames for a session
SELECT filename
FROM artifact
WHERE session_id = $1
ORDER BY sequence_number ASC;

-- name: DeleteArtifactByFilename :execrows
-- Delete artifact by session and filename
DELETE FROM artifact
WHERE session_id = $1 AND filename = $2;

-- name: DeleteArtifactsBySession :exec
-- Delete all artifacts for a session (called when session is deleted)
DELETE FROM artifact
WHERE session_id = $1;
