-- name: CreateReport :one
INSERT INTO reports (source, in_response_to, content, metadata, reported_date)
VALUES (@source, @in_response_to, @content, @metadata, @reported_date)
RETURNING id, source, in_response_to, content, metadata, reported_date, created_at;

-- name: ReportByID :one
SELECT id, source, in_response_to, content, metadata, reported_date, created_at
FROM reports WHERE id = @id;

-- name: ReportsByDirective :many
SELECT id, source, in_response_to, content, metadata, reported_date, created_at
FROM reports WHERE in_response_to = @directive_id
ORDER BY reported_date DESC, created_at DESC;

-- name: RecentReports :many
SELECT id, source, in_response_to, content, metadata, reported_date, created_at
FROM reports
ORDER BY reported_date DESC, created_at DESC;
