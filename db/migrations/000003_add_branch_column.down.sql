-- Rollback: Remove branch column from session_messages

DROP INDEX IF EXISTS idx_session_messages_branch;

ALTER TABLE session_messages
DROP CONSTRAINT IF EXISTS unique_session_branch_sequence;

ALTER TABLE session_messages
ADD CONSTRAINT unique_message_sequence UNIQUE (session_id, sequence_number);

CREATE INDEX IF NOT EXISTS idx_session_messages_sequence
ON session_messages(session_id, sequence_number);

ALTER TABLE session_messages
DROP COLUMN IF EXISTS branch;
