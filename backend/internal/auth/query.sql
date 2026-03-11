-- name: UserByEmail :one
SELECT id, email, role, created_at, updated_at
FROM users
WHERE email = $1;

-- name: UserByID :one
SELECT id, email, role, created_at, updated_at
FROM users
WHERE id = $1;

-- name: UpsertUserByEmail :one
INSERT INTO users (email, role)
VALUES ($1, 'admin')
ON CONFLICT (email) DO UPDATE SET updated_at = now()
RETURNING id, email, role, created_at, updated_at;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3);

-- name: RefreshTokenByHash :one
SELECT id, user_id, token_hash, expires_at, created_at
FROM refresh_tokens
WHERE token_hash = $1;

-- name: DeleteRefreshToken :exec
DELETE FROM refresh_tokens
WHERE token_hash = $1;

-- name: DeleteExpiredTokens :exec
DELETE FROM refresh_tokens
WHERE expires_at < now();
