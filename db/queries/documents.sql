-- Documents queries for sqlc
-- Generated code will be in internal/sqlc/documents.sql.go

-- name: UpsertDocument :exec
INSERT INTO documents (id, content, embedding, metadata, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, NOW())
ON CONFLICT (id) DO UPDATE SET
    content = EXCLUDED.content,
    embedding = EXCLUDED.embedding,
    metadata = EXCLUDED.metadata,
    updated_at = NOW();

-- name: SearchDocuments :many
SELECT id, content, metadata, created_at,
       (1 - (embedding <=> sqlc.arg(query_embedding)::vector))::float8 AS similarity
FROM documents
WHERE metadata @> sqlc.arg(filter_metadata)::jsonb
ORDER BY similarity DESC
LIMIT sqlc.arg(result_limit);

-- name: SearchDocumentsAll :many
SELECT id, content, metadata, created_at,
       (1 - (embedding <=> sqlc.arg(query_embedding)::vector))::float8 AS similarity
FROM documents
ORDER BY similarity DESC
LIMIT sqlc.arg(result_limit);

-- name: CountDocuments :one
SELECT COUNT(*)
FROM documents
WHERE metadata @> $1::jsonb;

-- name: CountDocumentsAll :one
SELECT COUNT(*)
FROM documents;

-- name: GetDocument :one
SELECT id, content, metadata, created_at, updated_at
FROM documents
WHERE id = $1;

-- name: DeleteDocument :exec
DELETE FROM documents
WHERE id = $1;

-- ===== Optimized RAG Queries (SQL-level filtering) =====

-- name: SearchBySourceType :many
-- Generic search by source_type (flexible for future source types)
SELECT id, content, metadata, created_at,
       (1 - (embedding <=> sqlc.arg(query_embedding)::vector))::float8 AS similarity
FROM documents
WHERE metadata->>'source_type' = sqlc.arg(source_type)::text
ORDER BY similarity DESC
LIMIT sqlc.arg(result_limit);

-- name: ListDocumentsBySourceType :many
-- List all documents by source_type without similarity calculation
-- Used for listing indexed files without needing embeddings
SELECT id, content, metadata, created_at, updated_at
FROM documents
WHERE metadata->>'source_type' = sqlc.arg(source_type)::text
ORDER BY created_at DESC
LIMIT sqlc.arg(result_limit);
