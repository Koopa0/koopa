-- Queries for the synthesis historical observation layer.
--
-- This is a write-once-read-many table. No UPDATE queries. Callers use
-- CreateSynthesis with ON CONFLICT DO NOTHING for dedup semantics —
-- same evidence set will not produce a duplicate row. Different
-- evidence produces a new row, enabling historical accumulation.

-- name: CreateSynthesis :one
-- Insert a new synthesis row. Caller must have already computed
-- evidence_hash via synthesis.ComputeEvidenceHash. ON CONFLICT on the
-- unique partial indexes (url_hash-style dedup) — either the by_key
-- or by_id partial index fires depending on which identity column is
-- populated. A conflict causes RETURNING to yield zero rows, which
-- the Go store maps to ErrNotFound and the caller interprets as
-- "already recorded with this evidence".
INSERT INTO syntheses (
    subject_type, subject_id, subject_key, kind,
    body, evidence, evidence_hash, computed_by
) VALUES (
    @subject_type, @subject_id, @subject_key, @kind,
    @body, @evidence, @evidence_hash, @computed_by
)
ON CONFLICT DO NOTHING
RETURNING id, subject_type, subject_id, subject_key, kind,
          body, evidence, evidence_hash, computed_at, computed_by;

-- name: RecentByKind :many
-- List recent syntheses for a (subject_type, kind) pair, newest first.
-- Used by the retrospective read endpoint to show a timeline of past
-- snapshots. Filters on subject_key optional so the caller can either
-- list all weeks or pin to one.
SELECT id, subject_type, subject_id, subject_key, kind,
       body, evidence, evidence_hash, computed_at, computed_by
FROM syntheses
WHERE subject_type = @subject_type
  AND kind = @kind
  AND (sqlc.narg('subject_key')::text IS NULL OR subject_key = sqlc.narg('subject_key'))
ORDER BY computed_at DESC
LIMIT $1;

-- name: LatestBySubjectKey :one
-- The most recent synthesis for a specific (subject_type, subject_key,
-- kind). Used when the reader wants "the best single snapshot we have
-- for week X" rather than the full timeline. Returns pgx.ErrNoRows on
-- no match, which the Go store maps to ErrNotFound.
SELECT id, subject_type, subject_id, subject_key, kind,
       body, evidence, evidence_hash, computed_at, computed_by
FROM syntheses
WHERE subject_type = @subject_type
  AND subject_key = @subject_key
  AND kind = @kind
ORDER BY computed_at DESC
LIMIT 1;

-- name: CountByKind :one
-- Row count for a (subject_type, kind). Used by integration tests to
-- verify invariants like "live weekly_summary leaves the table empty".
SELECT COUNT(*) FROM syntheses
WHERE subject_type = @subject_type AND kind = @kind;
