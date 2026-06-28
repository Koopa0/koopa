-- name: ContentByID :one
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, reading_time_min,
       cover_image, created_by, proposal_rationale, review_note, published_at, created_at, updated_at
FROM contents WHERE id = $1;

-- name: PublishedContents :many
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('since')::timestamptz IS NULL OR published_at >= sqlc.narg('since'))
ORDER BY published_at DESC NULLS LAST
LIMIT $1 OFFSET $2;

-- name: PublishedContentsCount :one
SELECT COUNT(*) FROM contents
WHERE status = 'published' AND is_public = true
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('since')::timestamptz IS NULL OR published_at >= sqlc.narg('since'));

-- name: ContentBySlug :one
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents WHERE slug = $1;

-- name: ContentsByTopicID :many
SELECT c.id, c.slug, c.title, c.body, c.excerpt, c.type, c.status,
       c.series_id, c.series_order,
       c.is_public, c.project_id, c.reading_time_min, c.cover_image,
       c.published_at, c.created_at, c.updated_at
FROM contents c
JOIN content_topics ct ON ct.content_id = c.id
WHERE ct.topic_id = $1 AND c.status = 'published' AND c.is_public = true
ORDER BY c.published_at DESC NULLS LAST
LIMIT $2 OFFSET $3;

-- name: ContentsByTopicIDCount :one
SELECT COUNT(*) FROM contents c
JOIN content_topics ct ON ct.content_id = c.id
WHERE ct.topic_id = $1 AND c.status = 'published' AND c.is_public = true;

-- name: SearchContents :many
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
  AND search_vector @@ websearch_to_tsquery('simple', $1)
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
ORDER BY ts_rank(search_vector, websearch_to_tsquery('simple', $1)) DESC
LIMIT $2 OFFSET $3;

-- name: SearchContentsCount :one
SELECT COUNT(*) FROM contents
WHERE status = 'published' AND is_public = true
  AND search_vector @@ websearch_to_tsquery('simple', $1)
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'));

-- name: InternalSearchContents :many
-- Internal FTS search without visibility filter (for MCP tools). Excludes
-- archived. Optional type/date filters are pushed into the WHERE so each
-- retrieval branch returns only matching rows BEFORE the RRF limit — a
-- content_type filter must not lose recall to a top-N full of other types.
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status != 'archived'
  AND search_vector @@ websearch_to_tsquery('simple', $1)
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('created_after')::timestamptz IS NULL OR created_at >= sqlc.narg('created_after'))
  AND (sqlc.narg('created_before')::timestamptz IS NULL OR created_at < sqlc.narg('created_before'))
ORDER BY ts_rank(search_vector, websearch_to_tsquery('simple', $1)) DESC
LIMIT $2 OFFSET $3;

-- name: InternalSemanticSearchContents :many
-- Semantic search over all contents via pgvector cosine distance. Mirrors
-- InternalSearchContents visibility (excludes only 'archived'); does NOT
-- exclude an anchor content id the way SimilarContents does, because this
-- is called from search_knowledge where there is no "current" content.
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, reading_time_min,
       cover_image, published_at, created_at, updated_at,
       (1 - (embedding <=> @target_embedding::vector))::float8 AS similarity
FROM contents
WHERE status != 'archived'
  AND embedding IS NOT NULL
  AND (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('created_after')::timestamptz IS NULL OR created_at >= sqlc.narg('created_after'))
  AND (sqlc.narg('created_before')::timestamptz IS NULL OR created_at < sqlc.narg('created_before'))
ORDER BY embedding <=> @target_embedding::vector
LIMIT @max_results;

-- name: PublishedForRSS :many
SELECT id, slug, title, excerpt, type, published_at, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
ORDER BY published_at DESC NULLS LAST
LIMIT $1;

-- name: ListContents :many
-- Admin list: all statuses, with optional type, status, and is_public filter.
SELECT id, slug, title, excerpt, type, status, is_public, project_id,
       reading_time_min, created_by, proposal_rationale, published_at, created_at, updated_at
FROM contents
WHERE (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('content_status')::content_status IS NULL OR status = sqlc.narg('content_status'))
  AND (sqlc.narg('is_public')::bool IS NULL OR is_public = sqlc.narg('is_public'))
  AND (sqlc.narg('project_id')::uuid IS NULL OR project_id = sqlc.narg('project_id'))
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountContents :one
SELECT COUNT(*) FROM contents
WHERE (sqlc.narg('content_type')::content_type IS NULL OR type = sqlc.narg('content_type'))
  AND (sqlc.narg('content_status')::content_status IS NULL OR status = sqlc.narg('content_status'))
  AND (sqlc.narg('is_public')::bool IS NULL OR is_public = sqlc.narg('is_public'))
  AND (sqlc.narg('project_id')::uuid IS NULL OR project_id = sqlc.narg('project_id'));

-- name: AllPublishedSlugs :many
SELECT slug, type, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
ORDER BY updated_at DESC;

-- name: ContentBriefsByProjectID :many
-- Minimal content projection (id, slug, title, type) linked to a project. Used
-- by the admin project detail endpoint to render the "related content" list
-- without pulling full bodies across the wire.
SELECT id, slug, title, type
FROM contents
WHERE project_id = @project_id
ORDER BY created_at DESC;

-- name: CreateContent :one
INSERT INTO contents (slug, title, body, excerpt, type, status,
                      series_id, series_order, is_public, project_id,
                      reading_time_min, cover_image, created_by, proposal_rationale)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, created_by, proposal_rationale, published_at, created_at, updated_at;

-- name: UpdateContent :one
UPDATE contents SET
    slug = COALESCE(sqlc.narg('slug'), slug),
    title = COALESCE(sqlc.narg('title'), title),
    body = COALESCE(sqlc.narg('body'), body),
    excerpt = COALESCE(sqlc.narg('excerpt'), excerpt),
    type = COALESCE(sqlc.narg('content_type')::content_type, type),
    status = COALESCE(sqlc.narg('status')::content_status, status),
    series_id = COALESCE(sqlc.narg('series_id'), series_id),
    series_order = COALESCE(sqlc.narg('series_order'), series_order),
    is_public = COALESCE(sqlc.narg('is_public'), is_public),
    project_id = COALESCE(sqlc.narg('project_id'), project_id),
    reading_time_min = COALESCE(sqlc.narg('reading_time_min'), reading_time_min),
    cover_image = COALESCE(sqlc.narg('cover_image'), cover_image),
    review_note = CASE
        WHEN COALESCE(sqlc.narg('status')::content_status, status) = 'changes_requested' THEN review_note
        ELSE NULL
    END,
    updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: PublishContent :one
-- Atomically sets status=published, is_public=true, and published_at.
-- Publishing always makes content publicly visible in this system.
UPDATE contents SET status = 'published', is_public = true, published_at = now(), review_note = NULL, updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: ArchiveContentReturning :one
-- Archive a content row and return the updated row. Both the REST archive
-- endpoint and DeleteContent use it — the RETURNING row lets a missing id
-- surface as ErrNotFound (→ 404) instead of a silent no-op.
UPDATE contents SET status = 'archived', review_note = NULL, updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: SubmitContentForReview :one
-- Transition content from draft to review. Returns pgx.ErrNoRows when the
-- row does not exist OR the current status is not 'draft' — the handler
-- translates "not found under this transition" into a 400 INVALID_STATE.
-- The WHERE-status guard makes the transition race-safe without a
-- separate read-then-write round trip.
UPDATE contents SET status = 'review', updated_at = now()
WHERE id = $1 AND status = 'draft'
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: RevertContentToDraft :one
-- Transition content from review back to draft (reviewer rejection path).
-- Same race-safe pattern as SubmitContentForReview; pgx.ErrNoRows means
-- "not in review state" which surfaces as 400 INVALID_STATE.
UPDATE contents SET status = 'draft', updated_at = now()
WHERE id = $1 AND status = 'review'
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, published_at, created_at, updated_at;

-- name: PublishedContentsInWindow :many
-- Content published within a [since, until] window, for
-- review_period.published_content. Sourced directly from the contents row
-- (status='published' guarantees published_at is non-null via
-- chk_content_publication), newest first.
SELECT title, type, published_at
FROM contents
WHERE status = 'published'
  AND published_at >= @since AND published_at <= @until
ORDER BY published_at DESC;

-- name: TopicsForContent :many
SELECT t.id, t.slug, t.name
FROM content_topics ct
JOIN topics t ON t.id = ct.topic_id
WHERE ct.content_id = $1;

-- name: TopicsForContents :many
SELECT ct.content_id, t.id, t.slug, t.name
FROM content_topics ct
JOIN topics t ON t.id = ct.topic_id
WHERE ct.content_id = ANY($1::uuid[]);

-- name: AddContentTopic :exec
INSERT INTO content_topics (content_id, topic_id) VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: DeleteContentTopics :exec
DELETE FROM content_topics WHERE content_id = $1;

-- name: ContentEmbeddingBySlug :one
SELECT id, embedding FROM contents WHERE slug = $1 AND status = 'published' AND is_public = true;

-- name: SimilarContents :many
SELECT c.id, c.slug, c.title, c.excerpt, c.type,
       (1 - (c.embedding <=> @target_embedding::vector))::float8 AS similarity
FROM contents c
WHERE c.status = 'published' AND c.is_public = true
  AND c.id != @exclude_id
  AND c.embedding IS NOT NULL
ORDER BY c.embedding <=> @target_embedding::vector
LIMIT @max_results;

-- name: PublishedWithEmbeddings :many
SELECT id, slug, title, type, embedding
FROM contents
WHERE status = 'published' AND is_public = true
  AND embedding IS NOT NULL;

-- name: ContentsMissingEmbedding :many
-- Rows the embedding reconciler still has to process. Archived content is
-- excluded — it is invisible to every search path (InternalSearchContents
-- and InternalSemanticSearchContents both filter it out), so embedding it
-- would spend API quota on unreachable rows. Oldest first so a backfill
-- progresses deterministically.
SELECT id, title, body
FROM contents
WHERE embedding IS NULL AND status != 'archived'
ORDER BY created_at
LIMIT $1;

-- name: SetContentEmbedding :exec
-- Persist a derived embedding. updated_at is deliberately untouched:
-- the embedding derives from title/body and carries no editorial change,
-- and updated_at orders admin lists and feeds lastmod semantics — a
-- background re-embed must not make content look freshly edited. The
-- contents audit trigger fires only on INSERT or UPDATE OF status, so
-- this write produces no activity_events row.
UPDATE contents SET embedding = $2 WHERE id = $1;

-- name: ContentsByStatus :many
-- List contents by status, ordered by updated_at descending. Used by admin pipeline.
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, reading_time_min,
       cover_image, published_at, created_at, updated_at
FROM contents
WHERE status = @status::content_status
ORDER BY updated_at DESC
LIMIT @max_results;

-- name: ContentIDBySlug :one
-- Fetch existing content id for a given slug. Used to return structured conflict info
-- when CreateContent hits a unique violation on the slug index.
SELECT id FROM contents WHERE slug = $1;

-- name: ContentsByCreator :many
-- List the content rows created by a given agent, newest first. Powers the
-- list_content MCP readback loop: an agent reads the disposition (status) of
-- the content it proposed, plus the owner's review_note when the owner sent a
-- draft back (status=changes_requested). created_by is the resolved caller
-- identity (caller-scoped), never a client-supplied filter.
SELECT id, slug, title, type, status, review_note, created_at
FROM contents
WHERE created_by = @created_by
ORDER BY created_at DESC;

-- name: ReviseContentByCreator :one
-- Caller-scoped revise for the revise_content MCP tool: an agent edits content
-- IT created that is in review or changes_requested, returning it to review and
-- clearing the owner's review_note. Each editable field uses COALESCE so an
-- omitted parameter leaves the column unchanged. The created_by + status guard
-- scopes the write to the caller's own revisable rows — a mismatched creator,
-- a wrong status, or an unknown id all match 0 rows (pgx.ErrNoRows → not-found),
-- never another agent's content and never a published row. created_by is the
-- resolved caller identity, never a client-supplied filter.
UPDATE contents SET
    body = COALESCE(sqlc.narg('body'), body),
    excerpt = COALESCE(sqlc.narg('excerpt'), excerpt),
    title = COALESCE(sqlc.narg('title'), title),
    status = 'review',
    review_note = NULL,
    updated_at = now()
WHERE id = @id AND created_by = @created_by
  AND status IN ('review', 'changes_requested')
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, created_by, proposal_rationale, review_note, published_at, created_at, updated_at;

-- name: SendContentChangesRequested :one
-- Admin send-back transition: the owner returns a review draft to the authoring
-- agent for revision (status → changes_requested) with a review_note reason. The
-- WHERE-status guard makes the transition race-safe: pgx.ErrNoRows means the row
-- is missing OR not in review (the store disambiguates into ErrNotFound vs
-- ErrInvalidState). review_note carries the owner's revision reason, read back by
-- the agent via list_content.
UPDATE contents SET
    status = 'changes_requested',
    review_note = @review_note,
    updated_at = now()
WHERE id = @id AND status = 'review'
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, created_by, proposal_rationale, review_note, published_at, created_at, updated_at;

