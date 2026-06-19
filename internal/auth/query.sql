-- name: UserByID :one
SELECT id, email, created_at, updated_at
FROM users
WHERE id = $1;

-- name: UpsertUserByEmail :one
INSERT INTO users (email)
VALUES ($1)
ON CONFLICT (email) DO UPDATE SET updated_at = now()
RETURNING id, email, created_at, updated_at;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3);

-- name: ConsumeRefreshToken :one
DELETE FROM refresh_tokens
WHERE token_hash = $1
RETURNING id, user_id, token_hash, expires_at, created_at;
