-- Extend the agents.platform closed set with 'codex' — the Codex CLI dev
-- collaborator runs in its own execution context. The set stays closed:
-- every value is an execution context the registry attributes writes to.
ALTER TABLE agents DROP CONSTRAINT chk_agent_platform;
ALTER TABLE agents ADD CONSTRAINT chk_agent_platform
    CHECK (platform IN ('claude-cowork', 'claude-code', 'claude-web', 'codex', 'human', 'system'));

COMMENT ON COLUMN agents.platform IS 'Execution context. Closed set: claude-cowork, claude-code, claude-web, codex, human, system (chk_agent_platform). The system value is reserved for the database-level fallback agent registered by BuiltinAgents — it attributes writes that bypass the Go actor middleware (pg_cron, manual psql ops, bug safety net). Routing decisions are driven by agent registry lookups, not this column.';
