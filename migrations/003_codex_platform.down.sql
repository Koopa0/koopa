-- Restore the pre-codex platform set. Requires that no agents row carries
-- platform='codex' — retire and re-point such rows before migrating down.
ALTER TABLE agents DROP CONSTRAINT chk_agent_platform;
ALTER TABLE agents ADD CONSTRAINT chk_agent_platform
    CHECK (platform IN ('claude-cowork', 'claude-code', 'claude-web', 'human', 'system'));

COMMENT ON COLUMN agents.platform IS 'Execution context. Closed set: claude-cowork, claude-code, claude-web, human, system (chk_agent_platform). The system value is reserved for the database-level fallback agent registered by BuiltinAgents — it attributes writes that bypass the Go actor middleware (pg_cron, manual psql ops, bug safety net). Routing decisions are driven by agent registry lookups, not this column.';
