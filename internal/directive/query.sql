-- name: CreateDirective :one
INSERT INTO directives (source, target, priority, content, metadata, issued_date)
VALUES (@source, @target, @priority, @content, @metadata, @issued_date)
RETURNING *;

-- name: DirectiveByID :one
SELECT * FROM directives WHERE id = @id;

-- name: AcknowledgeDirective :one
UPDATE directives
SET acknowledged_at = now(), acknowledged_by = @acknowledged_by
WHERE id = @id AND acknowledged_at IS NULL
RETURNING *;

-- name: ParticipantByName :one
SELECT name, platform, description, can_issue_directives, can_receive_directives,
       can_write_reports, task_assignable, can_own_schedules
FROM participant WHERE name = @name;

-- name: UnackedDirectivesForTarget :many
SELECT * FROM directives
WHERE target = @target AND acknowledged_at IS NULL
ORDER BY issued_date DESC, created_at DESC;

-- name: UnresolvedDirectivesForTarget :many
SELECT * FROM directives
WHERE target = @target AND acknowledged_at IS NOT NULL AND resolved_at IS NULL
ORDER BY issued_date DESC, created_at DESC;

-- name: UnackedIssuedBySource :many
-- Directives the caller issued that the target has not acknowledged yet.
SELECT * FROM directives
WHERE source = @source AND acknowledged_at IS NULL
ORDER BY issued_date DESC, created_at DESC;

-- name: UnresolvedIssuedBySource :many
-- Directives the caller issued that are acknowledged but not yet resolved.
SELECT * FROM directives
WHERE source = @source AND acknowledged_at IS NOT NULL AND resolved_at IS NULL
ORDER BY issued_date DESC, created_at DESC;

-- name: ResolveDirective :one
UPDATE directives
SET resolved_at = now(), resolution_report_id = @resolution_report_id
WHERE id = @id AND acknowledged_at IS NOT NULL AND resolved_at IS NULL
RETURNING *;

-- name: UnackedCount :one
-- Count of unacknowledged directives (for needs_attention badge).
SELECT count(*)::int FROM directives WHERE acknowledged_at IS NULL;

-- name: OpenDirectives :many
-- All unresolved directives (for studio IPC overview).
SELECT * FROM directives
WHERE resolved_at IS NULL
ORDER BY
    CASE priority WHEN 'p0' THEN 0 WHEN 'p1' THEN 1 ELSE 2 END,
    issued_date DESC;

-- name: ResolvedDirectivesRecent :many
-- Resolved directives, newest resolution first. For Directive Board history view.
SELECT * FROM directives
WHERE resolved_at IS NOT NULL
ORDER BY resolved_at DESC
LIMIT @max_results;

-- name: ParticipantsForStudio :many
-- Participants with directive and report counts for the Directive Board.
-- active_directives = unresolved directives where this participant is the target.
-- recent_reports = reports written by this participant since @since.
SELECT
    p.name,
    p.platform,
    p.can_issue_directives,
    p.can_receive_directives,
    p.can_write_reports,
    p.task_assignable,
    p.can_own_schedules,
    COALESCE(ad.cnt, 0)::int AS active_directives,
    COALESCE(rr.cnt, 0)::int AS recent_reports
FROM participant p
LEFT JOIN (
    SELECT target, count(*)::int AS cnt
    FROM directives
    WHERE resolved_at IS NULL
    GROUP BY target
) ad ON ad.target = p.name
LEFT JOIN (
    SELECT source, count(*)::int AS cnt
    FROM reports
    WHERE reported_date >= @since
    GROUP BY source
) rr ON rr.source = p.name
ORDER BY p.name;
