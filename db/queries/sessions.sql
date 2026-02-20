-- Sessions and messages queries for sqlc
-- Generated code will be in internal/sqlc/sessions.sql.go

-- name: CreateSession :one
INSERT INTO sessions (title, owner_id)
VALUES ($1, sqlc.arg(owner_id))
RETURNING id, title, owner_id, created_at, updated_at;

-- name: Session :one
SELECT id, title, owner_id, created_at, updated_at
FROM sessions
WHERE id = $1;

-- name: Sessions :many
SELECT id, title, owner_id, created_at, updated_at
FROM sessions
WHERE owner_id = sqlc.arg(owner_id)
ORDER BY updated_at DESC
LIMIT sqlc.arg(result_limit)
OFFSET sqlc.arg(result_offset);

-- name: SessionByIDAndOwner :one
-- Verify session exists and is owned by the given user.
-- Used for ownership checks without a separate query + comparison.
SELECT id, title, owner_id, created_at, updated_at
FROM sessions
WHERE id = sqlc.arg(session_id) AND owner_id = sqlc.arg(owner_id);

-- name: UpdateSessionUpdatedAt :execrows
UPDATE sessions
SET updated_at = NOW()
WHERE id = sqlc.arg(session_id);

-- name: UpdateSessionTitle :exec
-- Update session title (for auto-generation from first message or user edit)
UPDATE sessions
SET title = sqlc.arg(title),
    updated_at = NOW()
WHERE id = sqlc.arg(session_id);

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE id = $1;

-- name: AddMessage :exec
-- Add a message to a session
INSERT INTO messages (session_id, role, content, sequence_number, text_content)
VALUES ($1, $2, $3, $4, $5);

-- name: Messages :many
-- Get all messages for a session ordered by sequence
SELECT id, session_id, role, content, sequence_number, created_at
FROM messages
WHERE session_id = sqlc.arg(session_id)
ORDER BY sequence_number ASC
LIMIT sqlc.arg(result_limit)
OFFSET sqlc.arg(result_offset);

-- name: MaxSequenceNumber :one
-- Get max sequence number for a session (returns 0 if no messages)
SELECT COALESCE(MAX(sequence_number), 0)::integer AS max_seq
FROM messages
WHERE session_id = $1;

-- name: LockSession :one
-- Locks the session row to prevent concurrent modifications
SELECT id FROM sessions WHERE id = $1 FOR UPDATE;
