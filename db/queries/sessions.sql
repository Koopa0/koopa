-- Sessions queries for sqlc
-- Generated code will be in internal/sqlc/sessions.sql.go

-- name: CreateSession :one
INSERT INTO sessions (title, model_name, system_prompt)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetSession :one
SELECT id, title, created_at, updated_at, model_name, system_prompt, message_count
FROM sessions
WHERE id = $1;

-- name: ListSessions :many
SELECT id, title, created_at, updated_at, model_name, system_prompt, message_count
FROM sessions
ORDER BY updated_at DESC
LIMIT sqlc.arg(result_limit)
OFFSET sqlc.arg(result_offset);

-- name: UpdateSessionUpdatedAt :exec
UPDATE sessions
SET updated_at = NOW(),
    message_count = sqlc.arg(message_count)
WHERE id = sqlc.arg(session_id);

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE id = $1;

-- name: AddMessage :exec
INSERT INTO session_messages (session_id, role, content, sequence_number)
VALUES ($1, $2, $3, $4);

-- name: GetMessages :many
SELECT id, session_id, role, content, sequence_number, created_at
FROM session_messages
WHERE session_id = sqlc.arg(session_id)
ORDER BY sequence_number ASC
LIMIT sqlc.arg(result_limit)
OFFSET sqlc.arg(result_offset);

-- name: GetMaxSequenceNumber :one
SELECT COALESCE(MAX(sequence_number), 0) AS max_seq
FROM session_messages
WHERE session_id = $1;

-- name: LockSession :one
-- Locks the session row to prevent concurrent modifications (P1-2 fix)
-- Must be called within a transaction before GetMaxSequenceNumber
SELECT id FROM sessions WHERE id = $1 FOR UPDATE;
