-- name: EventsByTimeRange :many
-- List activity events within a time range, ordered by timestamp descending.
-- Sources exclusively from activity_events (internal entity state changes
-- written by AFTER triggers on covered tables). Hard cap prevents unbounded
-- result sets from wide time ranges. entity_title is the write-time snapshot
-- so a hard-deleted entity still renders meaningfully in the feed. actor is
-- the agent that caused the change (schema-mandatory NOT NULL) — exposed so
-- per-agent audit / timelines can attribute changes without a second JOIN.
SELECT a.id,
       a.entity_id::text AS entity_id,
       a.occurred_at     AS timestamp,
       a.change_kind,
       a.entity_type,
       a.actor,
       p.slug            AS project,
       a.entity_title    AS title,
       a.payload         AS metadata,
       a.created_at
FROM activity_events a
LEFT JOIN projects p ON p.id = a.project_id
WHERE a.occurred_at >= @start_time AND a.occurred_at < @end_time
ORDER BY a.occurred_at DESC
LIMIT 5000;

-- name: EventsByFilters :many
-- List activity events within a time range with optional entity_type, project,
-- and actor filters. entity_type matches activity_events.entity_type; project
-- matches the joined projects.slug; actors is a multi-value allowlist matching
-- activity_events.actor (NULL/empty → all actors). actor projection mirrors
-- EventsByTimeRange.
SELECT a.id,
       a.entity_id::text AS entity_id,
       a.occurred_at     AS timestamp,
       a.change_kind,
       a.entity_type,
       a.actor,
       p.slug            AS project,
       a.entity_title    AS title,
       a.payload         AS metadata,
       a.created_at
FROM activity_events a
LEFT JOIN projects p ON p.id = a.project_id
WHERE a.occurred_at >= @start_time AND a.occurred_at < @end_time
  AND (sqlc.narg('filter_entity_type')::text IS NULL OR a.entity_type = sqlc.narg('filter_entity_type'))
  AND (sqlc.narg('filter_project')::text IS NULL OR p.slug = sqlc.narg('filter_project'))
  AND (sqlc.narg('filter_actors')::text[] IS NULL OR a.actor = ANY(sqlc.narg('filter_actors')::text[]))
ORDER BY a.occurred_at DESC
LIMIT @max_results;
