-- Sessions queries for sqlc
-- Generated code will be in internal/sqlc/sessions.sql.go

-- name: CreateSession :one
INSERT INTO sessions (title, model_name, system_prompt)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetSession :one
SELECT id, title, created_at, updated_at, model_name, system_prompt, message_count, canvas_mode
FROM sessions
WHERE id = $1;

-- name: ListSessions :many
SELECT id, title, created_at, updated_at, model_name, system_prompt, message_count, canvas_mode
FROM sessions
ORDER BY updated_at DESC
LIMIT sqlc.arg(result_limit)
OFFSET sqlc.arg(result_offset);

-- name: ListSessionsWithMessages :many
-- Only list sessions that have messages or titles (not empty sessions)
-- This is used for sidebar to hide "New Chat" placeholder sessions
SELECT id, title, created_at, updated_at, model_name, system_prompt, message_count, canvas_mode
FROM sessions
WHERE message_count > 0 OR title IS NOT NULL
ORDER BY updated_at DESC
LIMIT sqlc.arg(result_limit)
OFFSET sqlc.arg(result_offset);

-- name: UpdateSessionUpdatedAt :exec
UPDATE sessions
SET updated_at = NOW(),
    message_count = sqlc.arg(message_count)
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
-- Legacy: adds message to 'main' branch
INSERT INTO message (session_id, role, content, sequence_number, branch)
VALUES ($1, $2, $3, $4, 'main');

-- name: AddMessageWithBranch :exec
-- Add a message to a specific branch
INSERT INTO message (session_id, branch, role, content, sequence_number)
VALUES ($1, $2, $3, $4, $5);

-- name: GetMessages :many
-- Legacy: returns all messages regardless of branch
SELECT *
FROM message
WHERE session_id = sqlc.arg(session_id)
ORDER BY sequence_number ASC
LIMIT sqlc.arg(result_limit)
OFFSET sqlc.arg(result_offset);

-- name: GetMessagesByBranch :many
-- Get messages for a specific session and branch
SELECT *
FROM message
WHERE session_id = sqlc.arg(session_id) AND branch = sqlc.arg(branch)
ORDER BY sequence_number ASC
LIMIT sqlc.arg(result_limit)
OFFSET sqlc.arg(result_offset);

-- name: GetMaxSequenceNumber :one
-- Legacy: max sequence across all branches
SELECT COALESCE(MAX(sequence_number), 0)::integer AS max_seq
FROM message
WHERE session_id = $1;

-- name: GetMaxSequenceByBranch :one
-- Get max sequence number for a specific branch
SELECT COALESCE(MAX(sequence_number), 0)::integer AS max_seq
FROM message
WHERE session_id = sqlc.arg(session_id) AND branch = sqlc.arg(branch);

-- name: CountMessagesByBranch :one
-- Count messages in a specific branch
SELECT COUNT(*)::integer AS count
FROM message
WHERE session_id = sqlc.arg(session_id) AND branch = sqlc.arg(branch);

-- name: LockSession :one
-- Locks the session row to prevent concurrent modifications
SELECT id FROM sessions WHERE id = $1 FOR UPDATE;

-- name: DeleteMessagesByBranch :exec
-- Delete all messages in a specific branch
DELETE FROM message
WHERE session_id = sqlc.arg(session_id) AND branch = sqlc.arg(branch);

-- name: AddMessageWithID :one
-- Add message with pre-assigned ID and status (for streaming)
INSERT INTO message (id, session_id, role, content, status, branch, sequence_number)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: UpdateMessageContent :exec
-- Update message content and mark as completed
UPDATE message
SET content = $2,
    status = 'completed',
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateMessageStatus :exec
-- Update message status (streaming/completed/failed)
UPDATE message
SET status = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: GetUserMessageBefore :one
-- Get the user message content immediately before a given sequence number.
-- Used by Stream handler to retrieve query without URL parameter.
SELECT content
FROM message
WHERE session_id = sqlc.arg(session_id)
  AND branch = sqlc.arg(branch)
  AND role = 'user'
  AND sequence_number < sqlc.arg(before_sequence)
ORDER BY sequence_number DESC
LIMIT 1;

-- name: GetMessageByID :one
-- Get a single message by ID (for streaming lookup).
SELECT *
FROM message
WHERE id = $1;

-- name: UpdateCanvasMode :exec
-- Toggle canvas mode for a session
UPDATE sessions
SET canvas_mode = sqlc.arg(canvas_mode),
    updated_at = NOW()
WHERE id = sqlc.arg(session_id);
