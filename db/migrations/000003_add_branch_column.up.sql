-- Add branch column to session_messages for conversation history isolation
-- Branch enables multi-agent scenarios where each agent maintains its own conversation history

-- Step 1: Add branch column with default value
ALTER TABLE session_messages
ADD COLUMN branch TEXT NOT NULL DEFAULT 'main';

-- Step 2: Drop the old unique constraint
ALTER TABLE session_messages
DROP CONSTRAINT IF EXISTS unique_message_sequence;

-- Step 3: Create new unique constraint including branch
ALTER TABLE session_messages
ADD CONSTRAINT unique_session_branch_sequence UNIQUE (session_id, branch, sequence_number);

-- Step 4: Create index for efficient branch queries
CREATE INDEX IF NOT EXISTS idx_session_messages_branch
ON session_messages(session_id, branch, sequence_number);

-- Step 5: Drop the old index (replaced by new composite index)
DROP INDEX IF EXISTS idx_session_messages_sequence;
