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
-- Legacy: adds message to 'main' branch
INSERT INTO session_messages (session_id, role, content, sequence_number, branch)
VALUES ($1, $2, $3, $4, 'main');

-- name: AddMessageWithBranch :exec
-- Add a message to a specific branch
INSERT INTO session_messages (session_id, branch, role, content, sequence_number)
VALUES ($1, $2, $3, $4, $5);

-- name: GetMessages :many
-- Legacy: returns all messages regardless of branch
SELECT id, session_id, role, content, sequence_number, created_at, branch
FROM session_messages
WHERE session_id = sqlc.arg(session_id)
ORDER BY sequence_number ASC
LIMIT sqlc.arg(result_limit)
OFFSET sqlc.arg(result_offset);

-- name: GetMessagesByBranch :many
-- Get messages for a specific session and branch
SELECT id, session_id, role, content, sequence_number, created_at, branch
FROM session_messages
WHERE session_id = sqlc.arg(session_id) AND branch = sqlc.arg(branch)
ORDER BY sequence_number ASC
LIMIT sqlc.arg(result_limit)
OFFSET sqlc.arg(result_offset);

-- name: GetMaxSequenceNumber :one
-- Legacy: max sequence across all branches
SELECT COALESCE(MAX(sequence_number), 0)::integer AS max_seq
FROM session_messages
WHERE session_id = $1;

-- name: GetMaxSequenceByBranch :one
-- Get max sequence number for a specific branch
SELECT COALESCE(MAX(sequence_number), 0)::integer AS max_seq
FROM session_messages
WHERE session_id = sqlc.arg(session_id) AND branch = sqlc.arg(branch);

-- name: CountMessagesByBranch :one
-- Count messages in a specific branch
SELECT COUNT(*)::integer AS count
FROM session_messages
WHERE session_id = sqlc.arg(session_id) AND branch = sqlc.arg(branch);

-- name: LockSession :one
-- Locks the session row to prevent concurrent modifications
SELECT id FROM sessions WHERE id = $1 FOR UPDATE;

-- name: DeleteMessagesByBranch :exec
-- Delete all messages in a specific branch
DELETE FROM session_messages
WHERE session_id = sqlc.arg(session_id) AND branch = sqlc.arg(branch);
