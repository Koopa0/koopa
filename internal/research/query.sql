-- Queries for the research package: fan-out research assignments and the
-- report corpus. See migrations/004_report_lane.up.sql for the schema.
--
-- trust_status and assignment status are TEXT + CHECK (not PG ENUMs), so they
-- map to plain Go strings — validation lives in the research package, not in a
-- generated enum type. reports.search_vector is a GENERATED column and is never
-- selected or written here (sqlc maps it to string via an override in
-- sqlc.yaml).

-- ---- research_assignments ------------------------------------------------

-- name: CreateAssignment :one
INSERT INTO research_assignments (topic, assigned_to, assigned_by)
VALUES ($1, $2, $3)
RETURNING id, topic, assigned_to, assigned_by, status, created_at, updated_at, fulfilled_at;

-- name: AssignmentByID :one
SELECT id, topic, assigned_to, assigned_by, status, created_at, updated_at, fulfilled_at
FROM research_assignments
WHERE id = $1;

-- name: OpenAssignments :many
-- Unfulfilled (open) assignments, newest first. This is how "a fan-out
-- assignment produced no report" stays visible — it sits here until a report
-- fulfills it.
SELECT id, topic, assigned_to, assigned_by, status, created_at, updated_at, fulfilled_at
FROM research_assignments
WHERE status = 'open'
ORDER BY created_at DESC
LIMIT @max_results;

-- name: FulfillAssignment :execrows
-- Flip open → fulfilled in the same transaction that creates the fulfilling
-- report. WHERE status = 'open' makes this idempotent: the first report
-- fulfills the assignment; a later report referencing the same (already
-- fulfilled) assignment affects 0 rows and is still created. fulfilled_at and
-- status move together to satisfy chk_research_assignment_fulfilled_pair.
UPDATE research_assignments
SET status = 'fulfilled', fulfilled_at = now(), updated_at = now()
WHERE id = $1 AND status = 'open';

-- ---- reports -------------------------------------------------------------

-- name: CreateReport :one
-- trust_status is intentionally NOT a parameter — every report is born
-- low_trust (column DEFAULT). Promotion to trusted is a separate human/admin
-- action (SetReportTrust), never part of report creation.
INSERT INTO reports (title, body, produced_by, origin_assignment_id)
VALUES ($1, $2, $3, $4)
RETURNING id, title, body, produced_by, origin_assignment_id, trust_status, created_at, updated_at;

-- name: ReportByID :one
SELECT id, title, body, produced_by, origin_assignment_id, trust_status, created_at, updated_at
FROM reports
WHERE id = $1;

-- name: SearchReports :many
-- FTS over reports.search_vector (title weight A, body weight C), relevance
-- ranked, capped by LIMIT. Mirrors SearchNotes. The MCP search_knowledge tool
-- unions these hits with content + note hits, then downranks reports by trust
-- in mergeByRelevance. Returns trust_status so the caller can badge + weight.
SELECT id, title, body, produced_by, origin_assignment_id, trust_status,
       created_at, updated_at,
       ts_rank(search_vector, websearch_to_tsquery('simple', @query)) AS rank
FROM reports
WHERE search_vector @@ websearch_to_tsquery('simple', @query)
ORDER BY rank DESC
LIMIT @max_results;

-- name: SetReportTrust :one
-- The writer for the human/admin trust verdict (low_trust → trusted or back).
-- Deliberately NOT wired to any agent-facing MCP tool — trust promotion is a
-- human decision, not an agent action.
UPDATE reports
SET trust_status = $2, updated_at = now()
WHERE id = $1
RETURNING id, title, body, produced_by, origin_assignment_id, trust_status, created_at, updated_at;
