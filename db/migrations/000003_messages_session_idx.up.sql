-- Add index on messages.session_id for JOIN performance.
-- PostgreSQL does NOT auto-create indexes on FK referencing columns.
-- SearchMessages and CountMessages both JOIN on m.session_id = s.id.
CREATE INDEX IF NOT EXISTS idx_messages_session_id ON messages(session_id);
