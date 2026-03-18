-- name: DueIntervals :many
-- List notes due for review, ordered by most overdue first.
SELECT si.note_id, si.easiness_factor, si.interval_days, si.repetitions,
       si.last_quality, si.due_at, si.reviewed_at, si.created_at,
       n.title, n.file_path, n.type, n.context
FROM spaced_intervals si
JOIN obsidian_notes n ON n.id = si.note_id
WHERE si.due_at <= now()
  AND (n.status IS NULL OR n.status != 'archived')
ORDER BY si.due_at ASC
LIMIT @max_results;

-- name: IntervalByNoteID :one
SELECT * FROM spaced_intervals WHERE note_id = $1;

-- name: UpsertInterval :one
INSERT INTO spaced_intervals (note_id, easiness_factor, interval_days, repetitions, last_quality, due_at, reviewed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (note_id) DO UPDATE SET
    easiness_factor = EXCLUDED.easiness_factor,
    interval_days = EXCLUDED.interval_days,
    repetitions = EXCLUDED.repetitions,
    last_quality = EXCLUDED.last_quality,
    due_at = EXCLUDED.due_at,
    reviewed_at = EXCLUDED.reviewed_at
RETURNING *;

-- name: InsertInterval :one
-- Insert a new interval; returns nothing if the note is already enrolled.
INSERT INTO spaced_intervals (note_id, easiness_factor, interval_days, repetitions, due_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (note_id) DO NOTHING
RETURNING *;

-- name: DueCount :one
SELECT count(*) FROM spaced_intervals si
JOIN obsidian_notes n ON n.id = si.note_id
WHERE si.due_at <= now()
  AND (n.status IS NULL OR n.status != 'archived');
