-- name: AddMessage :one
INSERT INTO messages (session_id, role, content, created_at)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: GetMessages :many
SELECT id, session_id, role, content, created_at
FROM messages
WHERE session_id = ?
ORDER BY created_at ASC
LIMIT ?;

-- name: GetAllMessages :many
SELECT id, session_id, role, content, created_at
FROM messages
WHERE session_id = ?
ORDER BY created_at ASC;

-- name: GetRecentMessages :many
SELECT id, session_id, role, content, created_at
FROM messages
WHERE session_id = ?
ORDER BY created_at DESC
LIMIT ?;
