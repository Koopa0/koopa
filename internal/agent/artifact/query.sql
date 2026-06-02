-- name: InsertArtifact :one
-- Insert a structured deliverable, optionally bound to a task. The
-- chk_artifacts_parts_count and chk_artifacts_parts_size CHECKs run here;
-- violations bubble up as 23514 and are mapped to ErrInvalidInput.
-- chk_artifacts_standalone_attribution enforces that standalone artifacts
-- have created_by set.
INSERT INTO artifacts (task_id, created_by, name, description, parts)
VALUES (@task_id, @created_by, @name, @description, @parts)
RETURNING id, task_id, created_by, name, description, parts, created_at;

-- name: ArtifactByID :one
SELECT id, task_id, created_by, name, description, parts, created_at
FROM artifacts WHERE id = @id;

-- name: ArtifactsForTask :many
-- All artifacts on a task in chronological order. Backed by idx_artifacts_task.
SELECT id, task_id, created_by, name, description, parts, created_at
FROM artifacts
WHERE task_id = @task_id
ORDER BY created_at ASC;

-- name: ArtifactCountForTask :one
SELECT COUNT(*)::int AS count
FROM artifacts WHERE task_id = @task_id;

-- name: RecentArtifacts :many
-- Most recent artifacts across all tasks. Used by admin studio overview.
SELECT id, task_id, created_by, name, description, parts, created_at
FROM artifacts
ORDER BY created_at DESC
LIMIT @max_results;
