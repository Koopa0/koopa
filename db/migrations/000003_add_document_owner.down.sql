DROP INDEX IF EXISTS idx_documents_owner;
ALTER TABLE documents DROP COLUMN IF EXISTS owner_id;
