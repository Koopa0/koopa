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

-- name: UnackedDirectivesForTarget :many
SELECT id, source, target, priority, acknowledged_at, acknowledged_by, content, metadata, issued_date, created_at
FROM directives
WHERE target = @target AND acknowledged_at IS NULL
ORDER BY issued_date DESC, created_at DESC;
