-- name: SetPreference :exec
INSERT OR REPLACE INTO preferences (key, value)
VALUES (?, ?);

-- name: GetPreference :one
SELECT key, value
FROM preferences
WHERE key = ?
LIMIT 1;

-- name: ListPreferences :many
SELECT key, value
FROM preferences
ORDER BY key;

-- name: DeletePreference :exec
DELETE FROM preferences WHERE key = ?;
