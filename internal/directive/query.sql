-- name: CreateDirective :one
INSERT INTO directives (source, target, priority, content, metadata, issued_date)
VALUES (@source, @target, @priority, @content, @metadata, @issued_date)
RETURNING id, source, target, priority, acknowledged_at, acknowledged_by, content, metadata, issued_date, created_at;

-- name: DirectiveByID :one
SELECT id, source, target, priority, acknowledged_at, acknowledged_by, content, metadata, issued_date, created_at
FROM directives WHERE id = @id;

-- name: AcknowledgeDirective :one
UPDATE directives
SET acknowledged_at = now(), acknowledged_by = @acknowledged_by
WHERE id = @id AND acknowledged_at IS NULL
RETURNING id, source, target, priority, acknowledged_at, acknowledged_by, content, metadata, issued_date, created_at;

-- name: ParticipantByName :one
SELECT name, platform, description, can_issue_directives, can_receive_directives,
       can_write_reports, task_assignable, can_own_schedules
FROM participant WHERE name = @name;

-- name: UnackedDirectivesForTarget :many
SELECT id, source, target, priority, acknowledged_at, acknowledged_by, content, metadata, issued_date, created_at
FROM directives
WHERE target = @target AND acknowledged_at IS NULL
ORDER BY issued_date DESC, created_at DESC;
