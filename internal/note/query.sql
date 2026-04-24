-- Queries for the note package. See migrations/001_initial.up.sql for the
-- notes table + note_concepts junction. slug uniqueness is enforced by the
-- UNIQUE constraint on notes.slug; callers rely on pgerrcode 23505 →
-- ErrConflict mapping. note_kind / note_maturity are PostgreSQL ENUMs.

-- name: CreateNote :one
INSERT INTO notes (
    slug, title, body, kind, maturity, created_by, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
)
RETURNING id, slug, title, body, kind, maturity, created_by,
          metadata, created_at, updated_at;

-- name: NoteByID :one
SELECT id, slug, title, body, kind, maturity, created_by,
       metadata, created_at, updated_at
FROM notes
WHERE id = $1;

-- name: NoteBySlug :one
SELECT id, slug, title, body, kind, maturity, created_by,
       metadata, created_at, updated_at
FROM notes
WHERE slug = $1;

-- name: Notes :many
SELECT id, slug, title, body, kind, maturity, created_by,
       metadata, created_at, updated_at
FROM notes
WHERE (sqlc.narg('kind')::note_kind IS NULL OR kind = sqlc.narg('kind'))
  AND (sqlc.narg('maturity')::note_maturity IS NULL OR maturity = sqlc.narg('maturity'))
ORDER BY updated_at DESC
LIMIT $1 OFFSET $2;

-- name: NotesCount :one
SELECT COUNT(*) FROM notes
WHERE (sqlc.narg('kind')::note_kind IS NULL OR kind = sqlc.narg('kind'))
  AND (sqlc.narg('maturity')::note_maturity IS NULL OR maturity = sqlc.narg('maturity'));

-- name: UpdateNote :one
-- Editable fields only. Maturity is intentionally separated — use
-- UpdateNoteMaturity so maturity transitions are distinct from body/title
-- edits.
UPDATE notes SET
    slug = COALESCE(sqlc.narg('slug'), slug),
    title = COALESCE(sqlc.narg('title'), title),
    body = COALESCE(sqlc.narg('body'), body),
    kind = COALESCE(sqlc.narg('kind')::note_kind, kind),
    metadata = COALESCE(sqlc.narg('metadata'), metadata),
    updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, kind, maturity, created_by,
          metadata, created_at, updated_at;

-- name: UpdateNoteMaturity :one
-- Transitions maturity explicitly. Any transition is permitted (including
-- → archived and recovery from archived); maturity is not a one-way state
-- machine at the schema level.
UPDATE notes SET
    maturity = @maturity::note_maturity,
    updated_at = now()
WHERE id = @id
RETURNING id, slug, title, body, kind, maturity, created_by,
          metadata, created_at, updated_at;

-- name: DeleteNote :execrows
DELETE FROM notes WHERE id = $1;

-- name: AddNoteConcept :exec
-- Link a note to a concept. Relevance defaults to 'primary'; caller passes
-- 'secondary' for supporting concepts.
INSERT INTO note_concepts (note_id, concept_id, relevance)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING;

-- name: DeleteNoteConcept :exec
DELETE FROM note_concepts WHERE note_id = $1 AND concept_id = $2;

-- name: ConceptsForNote :many
SELECT concept_id FROM note_concepts WHERE note_id = $1;

-- name: ConceptsForNotes :many
SELECT note_id, concept_id FROM note_concepts
WHERE note_id = ANY($1::uuid[]);

-- name: ConceptRefsForNote :many
-- Resolved concepts (slug + name) attached to a note — used by HTTP note
-- detail / list enrichment where wire consumers need human-readable slugs
-- instead of raw UUIDs.
SELECT c.id, c.slug, c.name
FROM note_concepts nc
JOIN concepts c ON c.id = nc.concept_id
WHERE nc.note_id = $1
ORDER BY c.name;

-- name: TargetRefsForNote :many
-- Learning targets attached to a note via the learning_target_notes
-- junction. Returned id + title are the minimum the admin note editor
-- surfaces; full target detail stays behind the learning endpoints.
SELECT lt.id, lt.title, lt.domain
FROM learning_target_notes ltn
JOIN learning_targets lt ON lt.id = ltn.learning_target_id
WHERE ltn.note_id = $1
ORDER BY lt.title;

-- name: SearchNotes :many
-- FTS over notes.search_vector (title weight A, body weight C). Returns
-- relevance-ranked rows capped by LIMIT. Query terms are websearch-style —
-- quotes and OR/- operators work. Used by the MCP search_knowledge tool to
-- union note hits with content hits.
SELECT id, slug, title, body, kind, maturity, created_by,
       metadata, created_at, updated_at,
       ts_rank(search_vector, websearch_to_tsquery('simple', @query)) AS rank
FROM notes
WHERE search_vector @@ websearch_to_tsquery('simple', @query)
ORDER BY rank DESC
LIMIT @max_results;
