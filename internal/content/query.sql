-- name: ContentByID :one
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, reading_time_min,
       cover_image, created_by, proposal_rationale, review_note,
       source_vault_path, source_git_blob_sha,
       published_at, created_at, updated_at
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

-- name: PublishedForRSS :many
SELECT id, slug, title, excerpt, type, published_at, updated_at
FROM contents
WHERE status = 'published' AND is_public = true
ORDER BY published_at DESC NULLS LAST
LIMIT $1;

-- name: ListContents :many
-- Admin list: all statuses, with optional type, status, and is_public filter.
SELECT id, slug, title, excerpt, type, status, is_public, project_id,
       reading_time_min, created_by, proposal_rationale,
       source_vault_path, source_git_blob_sha,
       published_at, created_at, updated_at
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
                      reading_time_min, cover_image, created_by, proposal_rationale,
                      source_vault_path, source_git_blob_sha)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, created_by, proposal_rationale,
          source_vault_path, source_git_blob_sha,
          published_at, created_at, updated_at;

-- name: UpdateContent :one
UPDATE contents SET
    slug = COALESCE(sqlc.narg('slug'), slug),
    title = COALESCE(sqlc.narg('title'), title),
    body = COALESCE(sqlc.narg('body'), body),
    excerpt = COALESCE(sqlc.narg('excerpt'), excerpt),
    type = COALESCE(sqlc.narg('content_type')::content_type, type),
    series_id = COALESCE(sqlc.narg('series_id'), series_id),
    series_order = COALESCE(sqlc.narg('series_order'), series_order),
    is_public = COALESCE(sqlc.narg('is_public'), is_public),
    project_id = COALESCE(sqlc.narg('project_id'), project_id),
    reading_time_min = COALESCE(sqlc.narg('reading_time_min'), reading_time_min),
    cover_image = COALESCE(sqlc.narg('cover_image'), cover_image),
    updated_at = now()
WHERE id = $1
  AND status <> 'published'
  AND source_vault_path IS NULL
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, source_vault_path, source_git_blob_sha,
          published_at, created_at, updated_at;

-- name: SetContentVisibility :one
-- Visibility is an operational exposure control, separate from editing the
-- authored publication snapshot. Durable withdrawal/restore semantics belong
-- to their own lifecycle transition rather than this boolean switch.
UPDATE contents SET is_public = $2, updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, source_vault_path, source_git_blob_sha,
          published_at, created_at, updated_at;

-- name: PublishContent :one
-- Atomically promotes only a source-bound draft/review snapshot. A missing
-- provenance pair, another lifecycle state, or an unknown id matches no row;
-- the store performs a read-only classification after the failed transition.
UPDATE contents SET status = 'published', is_public = true, published_at = now(), review_note = NULL, updated_at = now()
WHERE id = $1
  AND status IN ('draft', 'review')
  AND source_vault_path IS NOT NULL
  AND source_git_blob_sha IS NOT NULL
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, source_vault_path, source_git_blob_sha,
          published_at, created_at, updated_at;

-- name: ArchiveContentReturning :one
-- Archive a content row and return the updated row. Both the REST archive
-- endpoint and DeleteContent use it — the RETURNING row lets a missing id
-- surface as ErrNotFound (→ 404) instead of a silent no-op.
UPDATE contents SET status = 'archived', review_note = NULL, updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, source_vault_path, source_git_blob_sha,
          published_at, created_at, updated_at;

-- name: SubmitContentForReview :one
-- Transition content from draft to review. Returns pgx.ErrNoRows when the
-- row does not exist, the current status is not draft, or provenance is
-- missing. The store classifies the read-only rejection after this atomic
-- guard; it never authorizes the transition with a read-then-write check.
UPDATE contents SET status = 'review', updated_at = now()
WHERE id = $1 AND status = 'draft'
  AND source_vault_path IS NOT NULL
  AND source_git_blob_sha IS NOT NULL
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, source_vault_path, source_git_blob_sha,
          published_at, created_at, updated_at;

-- name: RevertContentToDraft :one
-- Transition content from review back to draft (reviewer rejection path).
-- Same race-safe pattern as SubmitContentForReview; pgx.ErrNoRows means
-- "not in review state" which surfaces as 400 INVALID_STATE.
UPDATE contents SET status = 'draft', updated_at = now()
WHERE id = $1 AND status = 'review'
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, source_vault_path, source_git_blob_sha,
          published_at, created_at, updated_at;

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

-- name: InsertContentTopics :exec
-- Bulk-insert content↔topic associations. Caller passes a uuid[] of topic
-- ids that all belong to the same content row. Runs inside the caller's
-- tx so partial writes roll back with the content insert/update. ON
-- CONFLICT DO NOTHING absorbs caller-side duplicates (same topic_id sent
-- twice) without leaking 23505 — idempotent per (content_id, topic_id) pair.
INSERT INTO content_topics (content_id, topic_id)
SELECT sqlc.arg('content_id')::uuid, UNNEST(sqlc.arg('topic_ids')::uuid[])
ON CONFLICT DO NOTHING;

-- name: DeleteContentTopics :exec
DELETE FROM content_topics WHERE content_id = $1;

-- name: ContentsByStatus :many
-- List contents by status, ordered by updated_at descending. Used by admin pipeline.
SELECT id, slug, title, body, excerpt, type, status,
       series_id, series_order, is_public, project_id, reading_time_min,
       cover_image, source_vault_path, source_git_blob_sha,
       published_at, created_at, updated_at
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
SELECT id, slug, title, type, status, review_note,
       source_vault_path, source_git_blob_sha, published_at, created_at
FROM contents
WHERE created_by = @created_by
ORDER BY created_at DESC;

-- name: ReviseContentByCreator :one
-- Caller-scoped full snapshot replacement for revise_content. All authored
-- fields and the provenance pair move together; reusing the existing blob SHA
-- matches no row. The caller/status guard never exposes another agent's row.
UPDATE contents SET
    body = @body,
    excerpt = @excerpt,
    title = @title,
    source_vault_path = @source_vault_path,
    source_git_blob_sha = @source_git_blob_sha,
    status = 'review',
    review_note = NULL,
    updated_at = now()
WHERE id = @id AND created_by = @created_by
  AND status IN ('review', 'changes_requested')
  AND source_git_blob_sha IS DISTINCT FROM @source_git_blob_sha
RETURNING id, slug, title, body, excerpt, type, status,
          series_id, series_order, is_public, project_id, reading_time_min,
          cover_image, created_by, proposal_rationale, review_note,
          source_vault_path, source_git_blob_sha,
          published_at, created_at, updated_at;

-- name: RevisableContentSourceByCreator :one
-- Read-only rejection classifier for revise_content. Caller/status scoping is
-- identical to the update so it cannot reveal another agent's row.
SELECT source_git_blob_sha
FROM contents
WHERE id = @id AND created_by = @created_by
  AND status IN ('review', 'changes_requested');

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
          cover_image, created_by, proposal_rationale, review_note,
          source_vault_path, source_git_blob_sha,
          published_at, created_at, updated_at;
