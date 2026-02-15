-- Add owner_id to documents for per-user knowledge isolation.
-- Prevents RAG poisoning: user A's stored knowledge cannot influence user B's results.
-- Existing documents get NULL owner_id (legacy/shared — visible to all users).
ALTER TABLE documents ADD COLUMN owner_id TEXT;

CREATE INDEX idx_documents_owner ON documents(owner_id);
