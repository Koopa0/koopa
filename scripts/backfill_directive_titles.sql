-- backfill_directive_titles.sql
--
-- One-shot fix for `tasks` rows whose title is the placeholder
-- "Directive" — fixtures created before
-- propose_directive started extracting the title from
-- request_parts[0].text. After commit `8281f7e` (feat(mcp): strict
-- directive title from request_parts[0].text) every NEW directive lands
-- with a meaningful title, but pre-existing rows keep "Directive" as
-- their title and pollute morning_context.pending_tasks_issued
-- readability.
--
-- This script extracts the first text part from each affected task's
-- earliest request message and rewrites the title in place. It is
-- idempotent — re-running it leaves correct titles untouched and only
-- updates rows that still match the placeholder filter.
--
-- Usage:
--   psql "$DATABASE_URL" -f scripts/backfill_directive_titles.sql
--
-- Safety:
--   - WHERE filter is exact "Directive" — does not touch user titles
--     that happen to contain the word.
--   - The CTE picks the request message with the smallest position so
--     we always read the original ask, not a later revision message.
--   - Title is truncated to 200 runes to match the
--     directiveTitleMaxRunes contract in propose_flat.go (commitment.go
--     resolveDirectiveFields). Trailing whitespace is trimmed; no
--     ellipsis is added — the morning_context list view truncates
--     visually, and storing the marker character would diverge from
--     fresh-write semantics.
--   - Rows whose first request message has no text part remain titled
--     "Directive" so a human can inspect them — silently dropping them
--     would hide bad fixtures.

BEGIN;

WITH first_request_text AS (
    SELECT DISTINCT ON (tm.task_id)
        tm.task_id,
        -- Extract the first part of the JSONB array, then read its
        -- "text" key. Returns NULL if the part is data-only.
        (tm.parts -> 0 ->> 'text') AS extracted_text
    FROM task_messages tm
    WHERE tm.role = 'request'
    ORDER BY tm.task_id, tm.position ASC
)
UPDATE tasks t
SET title = LEFT(btrim(frt.extracted_text), 200),
    updated_at = now()
FROM first_request_text frt
WHERE t.id = frt.task_id
  AND t.title = 'Directive'
  AND frt.extracted_text IS NOT NULL
  AND btrim(frt.extracted_text) <> '';

COMMIT;

-- Quick audit: how many directives still carry the placeholder after
-- the backfill (typically: data-only first parts that the script
-- intentionally leaves alone).
SELECT count(*) AS remaining_placeholder_titles
FROM tasks
WHERE title = 'Directive';
