-- Rollback schema migration

DROP TRIGGER IF EXISTS update_documents_updated_at ON documents;
DROP FUNCTION IF EXISTS update_updated_at_column();

DROP INDEX IF EXISTS metadata_session_id_idx;
DROP INDEX IF EXISTS metadata_source_type_idx;
DROP INDEX IF EXISTS metadata_gin_idx;
DROP INDEX IF EXISTS embedding_hnsw_idx;

DROP TABLE IF EXISTS documents;

DROP EXTENSION IF EXISTS vector;
