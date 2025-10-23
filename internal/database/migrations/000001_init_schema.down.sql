-- 回滾順序很重要：先刪除索引，再刪除表（因為外鍵約束）

DROP INDEX IF EXISTS idx_sessions_created_at;
DROP INDEX IF EXISTS idx_messages_created_at;
DROP INDEX IF EXISTS idx_messages_session_id;

DROP TABLE IF EXISTS preferences;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS sessions;
