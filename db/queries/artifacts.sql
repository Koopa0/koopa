-- Artifact queries for sqlc
-- Canvas Mode Comprehensive Fixes

-- name: CreateArtifact :one
-- Create a new artifact for canvas panel (autosave)
INSERT INTO session_artifacts (
    session_id,
    message_id,
    type,
    language,
    title,
    content,
    sequence_number
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    COALESCE((SELECT MAX(sequence_number) + 1 FROM session_artifacts WHERE session_id = $1), 1)
)
RETURNING *;

-- name: GetLatestArtifact :one
-- Get the most recent artifact for a session (canvas panel display)
SELECT *
FROM session_artifacts
WHERE session_id = $1
ORDER BY created_at DESC
LIMIT 1;

-- name: ListArtifactsBySession :many
-- List artifacts for a session, newest first
SELECT *
FROM session_artifacts
WHERE session_id = $1
ORDER BY sequence_number DESC
LIMIT sqlc.arg(result_limit)
OFFSET sqlc.arg(result_offset);

-- name: UpdateArtifactContent :exec
-- Update artifact content (for future interactive editing)
UPDATE session_artifacts
SET content = $2,
    version = version + 1,
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteArtifact :exec
-- Delete an artifact
DELETE FROM session_artifacts
WHERE id = $1;
