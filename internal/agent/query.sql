-- name: ListAgents :many
-- Snapshot of every row in the agents table, ordered by name. Used by
-- agent.SyncToTable to reconcile the Go BuiltinAgents() literal against
-- the DB projection.
SELECT name, display_name, platform, description, status, synced_at, retired_at
FROM agents
ORDER BY name;

-- name: UpsertAgent :exec
-- Write an active agent row. ON CONFLICT clears any previous retirement —
-- a registered agent is always active after sync. Called once per entry
-- in BuiltinAgents() during startup reconciliation.
INSERT INTO agents (name, display_name, platform, description, status, synced_at, retired_at)
VALUES (@name, @display_name, @platform, @description, 'active', now(), NULL)
ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    platform     = EXCLUDED.platform,
    description  = EXCLUDED.description,
    status       = 'active',
    synced_at    = now(),
    retired_at   = NULL;

-- name: RetireAgent :execrows
-- Mark an existing agent row as retired. No-op if already retired
-- (retired_at preserved via COALESCE). Returns rows-affected so the
-- caller can detect "retired a row that was never registered" vs
-- "no such agent".
UPDATE agents
SET status     = 'retired',
    retired_at = COALESCE(retired_at, now()),
    synced_at  = now()
WHERE name = @name;
