-- name: ListAgents :many
-- Snapshot of every row in the agents table, ordered by name. Used by
-- agent.SyncToTable to reconcile the Go BuiltinAgents() literal against
-- the DB projection.
SELECT name, display_name, platform, description, status, synced_at, retired_at
FROM agents
ORDER BY name;

-- name: UpsertAgents :exec
-- Batch-writes every registered agent as active in one round trip. ON
-- CONFLICT clears any previous retirement — a registered agent is always
-- active after sync. Called once per SyncToTable run with the full
-- BuiltinAgents() literal.
INSERT INTO agents (name, display_name, platform, description, status, synced_at, retired_at)
SELECT n, dn, p, d, 'active', now(), NULL
FROM ROWS FROM (
    unnest(@names::text[]),
    unnest(@display_names::text[]),
    unnest(@platforms::text[]),
    unnest(@descriptions::text[])
) AS x(n, dn, p, d)
ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    platform     = EXCLUDED.platform,
    description  = EXCLUDED.description,
    status       = 'active',
    synced_at    = now(),
    retired_at   = NULL;

-- name: RetireAgents :execrows
-- Batch-marks a set of existing agent rows as retired in one round trip.
-- No-op per row if already retired (retired_at preserved via COALESCE).
-- Returns total rows affected, so the caller can detect a name that
-- matched no row (affected < len(names)).
UPDATE agents
SET status     = 'retired',
    retired_at = COALESCE(retired_at, now()),
    synced_at  = now()
WHERE name = ANY(@names::text[]);
