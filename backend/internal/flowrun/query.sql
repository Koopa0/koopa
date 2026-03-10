-- name: CreateFlowRun :one
INSERT INTO flow_runs (flow_name, content_id, input)
VALUES ($1, $2, $3)
RETURNING id, flow_name, content_id, input, output, status, error, attempt, max_attempts, started_at, ended_at, created_at;

-- name: FlowRunByID :one
SELECT id, flow_name, content_id, input, output, status, error, attempt, max_attempts, started_at, ended_at, created_at
FROM flow_runs WHERE id = $1;

-- name: FlowRuns :many
SELECT id, flow_name, content_id, input, output, status, error, attempt, max_attempts, started_at, ended_at, created_at
FROM flow_runs
WHERE (sqlc.narg('status')::flow_status IS NULL OR status = sqlc.narg('status'))
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: FlowRunsCount :one
SELECT COUNT(*) FROM flow_runs
WHERE (sqlc.narg('status')::flow_status IS NULL OR status = sqlc.narg('status'));

-- name: UpdateFlowRunRunning :exec
UPDATE flow_runs SET status = 'running', started_at = now(), attempt = attempt + 1
WHERE id = $1;

-- name: UpdateFlowRunCompleted :exec
UPDATE flow_runs SET status = 'completed', output = $2, ended_at = now()
WHERE id = $1;

-- name: UpdateFlowRunFailed :exec
UPDATE flow_runs SET status = 'failed', error = $2, ended_at = now()
WHERE id = $1;

-- name: RetryableFlowRuns :many
UPDATE flow_runs SET status = 'pending'
WHERE (status = 'failed' AND attempt < max_attempts)
   OR (status = 'pending' AND attempt < max_attempts AND created_at < now() - INTERVAL '5 minutes')
   OR (status = 'running' AND attempt < max_attempts AND started_at < now() - INTERVAL '10 minutes')
RETURNING id, flow_name, content_id, input, output, status, error, attempt, max_attempts, started_at, ended_at, created_at;

-- name: PendingRunExists :one
SELECT EXISTS(
    SELECT 1 FROM flow_runs
    WHERE flow_name = $1 AND content_id = $2 AND status IN ('pending', 'running')
) AS exists;

-- name: LatestCompletedRunByContentAndFlow :one
SELECT id, flow_name, content_id, input, output, status, error, attempt, max_attempts, started_at, ended_at, created_at
FROM flow_runs
WHERE flow_name = $1 AND content_id = $2 AND status = 'completed'
ORDER BY ended_at DESC
LIMIT 1;
