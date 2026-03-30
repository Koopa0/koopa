-- name: InsertReconcileRun :one
INSERT INTO reconcile_runs (
    started_at, completed_at,
    obsidian_missing, obsidian_orphaned,
    notion_proj_missing, notion_proj_orphan,
    notion_goal_missing, notion_goal_orphan,
    total_drift, error_count, errors
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id;

-- name: RecentReconcileRuns :many
SELECT id, started_at, completed_at,
       obsidian_missing, obsidian_orphaned,
       notion_proj_missing, notion_proj_orphan,
       notion_goal_missing, notion_goal_orphan,
       total_drift, error_count, errors, created_at
FROM reconcile_runs
ORDER BY started_at DESC
LIMIT $1;
