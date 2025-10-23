-- name: CreateSession :one
INSERT INTO sessions (title, created_at, updated_at)
VALUES (?, ?, ?)
RETURNING *;

-- name: GetSession :one
SELECT id, title, created_at, updated_at
FROM sessions
WHERE id = ?
LIMIT 1;

-- name: ListSessions :many
SELECT id, title, created_at, updated_at
FROM sessions
ORDER BY updated_at DESC
LIMIT ?;

-- name: UpdateSessionTitle :exec
UPDATE sessions
SET title = ?, updated_at = ?
WHERE id = ?;

-- name: UpdateSessionTimestamp :exec
UPDATE sessions
SET updated_at = ?
WHERE id = ?;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = ?;
