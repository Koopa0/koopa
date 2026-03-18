-- Stage 3: B1/B3 End-to-End Pipeline Verification Queries
-- Run these after triggering an Obsidian push and a non-Obsidian repo push.

-- 1. Obsidian notes (B1): check upserted records
SELECT id, file_path, type, status, title,
       array_length(string_to_array(tags::text, ','), 1) AS tag_count,
       content_hash IS NOT NULL AS has_hash,
       synced_at
FROM obsidian_notes
ORDER BY synced_at DESC
LIMIT 10;

-- 2. Note-tag junction (B1): check tag normalization worked
SELECT n.file_path, t.slug AS tag_slug, t.name AS tag_name
FROM obsidian_note_tags nt
JOIN obsidian_notes n ON n.id = nt.note_id
JOIN tags t ON t.id = nt.tag_id
ORDER BY n.synced_at DESC
LIMIT 20;

-- 3. Activity events — all sources
SELECT id, source, event_type, source_id, title,
       project, metadata IS NOT NULL AS has_metadata,
       created_at
FROM activity_events
ORDER BY created_at DESC
LIMIT 20;

-- 4. Activity events — Obsidian source only (B1 gap fix verification)
SELECT id, event_type, source_id, title, project,
       metadata->>'note_type' AS note_type,
       metadata->>'file_path' AS file_path,
       created_at
FROM activity_events
WHERE source = 'obsidian'
ORDER BY created_at DESC
LIMIT 10;

-- 5. Activity events — GitHub source only (B3 verification)
SELECT id, event_type, source_id, title, repo,
       metadata->>'lines_added' AS lines_added,
       metadata->>'lines_removed' AS lines_removed,
       metadata->>'files_changed' AS files_changed,
       created_at
FROM activity_events
WHERE source = 'github'
ORDER BY created_at DESC
LIMIT 10;

-- 6. Activity event tags (B1 — only Obsidian events should have tags)
SELECT ae.source, ae.event_type, ae.title, t.slug AS tag_slug
FROM activity_event_tags aet
JOIN activity_events ae ON ae.id = aet.event_id
JOIN tags t ON t.id = aet.tag_id
ORDER BY ae.created_at DESC
LIMIT 20;

-- 7. Unmapped aliases (tag normalization edge cases)
SELECT id, raw_tag, match_method, confirmed, created_at
FROM tag_aliases
WHERE tag_id IS NULL
ORDER BY created_at DESC
LIMIT 10;

-- 8. Summary counts
SELECT
    (SELECT count(*) FROM obsidian_notes) AS total_notes,
    (SELECT count(*) FROM obsidian_note_tags) AS total_note_tags,
    (SELECT count(*) FROM activity_events) AS total_events,
    (SELECT count(*) FROM activity_events WHERE source = 'obsidian') AS obsidian_events,
    (SELECT count(*) FROM activity_events WHERE source = 'github') AS github_events,
    (SELECT count(*) FROM activity_event_tags) AS total_event_tags,
    (SELECT count(*) FROM tag_aliases WHERE tag_id IS NULL) AS unmapped_aliases;
