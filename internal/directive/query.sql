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

-- name: ResolveDirective :one
UPDATE directives
SET resolved_at = now(), resolution_report_id = @resolution_report_id
WHERE id = @id AND acknowledged_at IS NOT NULL AND resolved_at IS NULL
RETURNING *;
