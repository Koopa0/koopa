-- name: UpsertNote :one
INSERT INTO obsidian_notes (
    file_path, title, type, provenance, context, maturity, raw_tags,
    difficulty, leetcode_id, book, chapter, external_provider, external_ref,
    content_text, content_hash, synced_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13,
    $14, $15, now()
)
ON CONFLICT (file_path) DO UPDATE SET
    title = EXCLUDED.title,
    type = EXCLUDED.type,
    provenance = EXCLUDED.provenance,
    context = EXCLUDED.context,
    maturity = EXCLUDED.maturity,
    raw_tags = EXCLUDED.raw_tags,
    difficulty = EXCLUDED.difficulty,
    leetcode_id = EXCLUDED.leetcode_id,
    book = EXCLUDED.book,
    chapter = EXCLUDED.chapter,
    external_provider = EXCLUDED.external_provider,
    external_ref = EXCLUDED.external_ref,
    content_text = EXCLUDED.content_text,
    content_hash = EXCLUDED.content_hash,
    synced_at = now()
RETURNING *;

-- name: NoteByFilePath :one
SELECT * FROM obsidian_notes WHERE file_path = $1;

-- name: NoteContentHash :one
SELECT content_hash FROM obsidian_notes WHERE file_path = $1;

-- name: ArchiveNote :exec
UPDATE obsidian_notes SET maturity = 'archived', synced_at = now()
WHERE file_path = $1 AND maturity != 'archived';

-- name: SearchNotesByText :many
-- Full-text search on obsidian_notes using the search_vector GIN index.
-- Uses websearch_to_tsquery('simple', ...) for user-friendly query syntax.
SELECT id, file_path, title, type, provenance, context, maturity, raw_tags,
       difficulty, book, chapter, content_text, synced_at,
       ts_rank(search_vector, websearch_to_tsquery('simple', @query)) AS rank
FROM obsidian_notes
WHERE search_vector @@ websearch_to_tsquery('simple', @query)
  AND (maturity IS NULL OR maturity != 'archived')
ORDER BY rank DESC
LIMIT @max_results;

-- name: SearchNotesByFilters :many
-- Filter obsidian_notes by frontmatter fields and date range. NULL parameters are ignored.
SELECT id, file_path, title, type, provenance, context, maturity, raw_tags,
       difficulty, book, chapter, content_text, synced_at
FROM obsidian_notes
WHERE (maturity IS NULL OR maturity != 'archived')
  AND (sqlc.narg('filter_type')::text IS NULL OR type = sqlc.narg('filter_type'))
  AND (sqlc.narg('filter_provenance')::text IS NULL OR provenance = sqlc.narg('filter_provenance'))
  AND (sqlc.narg('filter_context')::text IS NULL OR context = sqlc.narg('filter_context'))
  AND (sqlc.narg('filter_book')::text IS NULL OR book = sqlc.narg('filter_book'))
  AND (sqlc.narg('after')::timestamptz IS NULL OR synced_at >= sqlc.narg('after'))
  AND (sqlc.narg('before')::timestamptz IS NULL OR synced_at < sqlc.narg('before'))
ORDER BY synced_at DESC
LIMIT @max_results;

-- name: NotesByTypeAndContext :many
-- List obsidian_notes by type, optionally filtered by context. Used for decision-log retrieval.
SELECT id, file_path, title, type, provenance, context, maturity, raw_tags,
       difficulty, book, chapter, content_text, synced_at
FROM obsidian_notes
WHERE type = @note_type
  AND (maturity IS NULL OR maturity != 'archived')
  AND (sqlc.narg('filter_context')::text IS NULL OR context = sqlc.narg('filter_context'))
ORDER BY synced_at DESC
LIMIT @max_results;

-- name: UpdateNoteEmbedding :exec
-- Store embedding vector for a note.
UPDATE obsidian_notes SET embedding = $2 WHERE id = $1;

-- name: NotesWithoutEmbedding :many
-- Find obsidian_notes that need embedding generation.
SELECT id, file_path, title, content_text
FROM obsidian_notes
WHERE embedding IS NULL AND (maturity IS NULL OR maturity != 'archived')
ORDER BY synced_at DESC
LIMIT @batch_size;

-- name: SearchNotesBySimilarity :many
-- Semantic search: find obsidian_notes closest to a query embedding vector.
SELECT id, file_path, title, type, provenance, context, maturity, raw_tags,
       difficulty, book, chapter, content_text, synced_at,
       (1 - (embedding <=> @query_embedding::vector))::float8 AS similarity
FROM obsidian_notes
WHERE embedding IS NOT NULL
  AND (maturity IS NULL OR maturity != 'archived')
ORDER BY embedding <=> @query_embedding::vector
LIMIT @max_results;

-- name: DeleteNoteLinksByNoteID :exec
-- Remove all wikilink edges for a note before re-sync.
DELETE FROM obsidian_note_links WHERE source_note_id = $1;

-- name: UpsertNoteLink :exec
-- Insert or update a wikilink edge.
INSERT INTO obsidian_note_links (source_note_id, target_path, link_text)
VALUES ($1, $2, $3)
ON CONFLICT (source_note_id, target_path) DO UPDATE SET
    link_text = EXCLUDED.link_text;

-- name: BulkUpsertNoteLinks :exec
-- Batch insert/update wikilink edges using unnest for performance.
-- Replaces the N+1 loop pattern in SyncNoteLinks.
INSERT INTO obsidian_note_links (source_note_id, target_path, link_text)
SELECT @source_note_id, unnest(@target_paths::text[]), unnest(@link_texts::text[])
ON CONFLICT (source_note_id, target_path) DO UPDATE SET
    link_text = EXCLUDED.link_text;
