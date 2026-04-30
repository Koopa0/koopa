-- cleanup_pending_dups.sql
--
-- Cancel duplicate pending directives that accumulate when audit /
-- test runs simulate the same Koopa input multiple times. After
-- several rounds of `Phase 1 audit` the morning_context briefing
-- view fills up with repeated "Fix README typo" / "Evaluate NATS
-- exactly-once" rows that are all the same intent submitted on
-- different days — making the readability of pending_tasks_issued
-- degrade fast.
--
-- This is an OPERATIONAL script, not a migration. Run after audit
-- sessions to keep the briefing readable. In production the same
-- script catches accidental re-delegation of identical work.
--
-- Detection rule:
--   "duplicate" = same (title, created_by, assignee) appearing >1
--   times in (state IN ('submitted', 'working')).
--
-- Resolution rule:
--   keep the most recent submitted_at for each duplicate group;
--   cancel the older copies (state → canceled, canceled_at = now()).
--   Cancellation preserves activity_events history; nothing is
--   deleted.
--
-- Usage:
--   1. Run the SELECT block first. Inspect the candidate list.
--   2. If list looks right, uncomment the BEGIN ... COMMIT block.
--   3. Re-run.
--
-- Safety:
--   - Only cancels (never deletes). Reversible by direct UPDATE if
--     the wrong row got hit.
--   - WHERE state IN ('submitted', 'working') so completed /
--     already-canceled / revision_requested rows are untouched.
--   - PARTITION BY (title, created_by, assignee) ensures the row
--     identity dimension is the title-as-intent, not the row id —
--     same title from different sources is NOT collapsed.

-- =====================================================================
-- 1. Review candidates: which directives WOULD be canceled
-- =====================================================================
WITH ranked AS (
    SELECT
        id, title, created_by, assignee, state, submitted_at,
        ROW_NUMBER() OVER (
            PARTITION BY title, created_by, assignee
            ORDER BY submitted_at DESC
        ) AS recency_rank,
        COUNT(*) OVER (
            PARTITION BY title, created_by, assignee
        ) AS dup_count
    FROM tasks
    WHERE state IN ('submitted', 'working')
)
SELECT
    id, title, created_by, assignee, state,
    submitted_at,
    age(now(), submitted_at) AS age,
    dup_count,
    CASE WHEN recency_rank = 1 THEN 'KEEP' ELSE 'CANCEL' END AS action
FROM ranked
WHERE dup_count > 1
ORDER BY title, submitted_at DESC;

-- =====================================================================
-- 2. Bulk cancel older duplicates (uncomment to run)
-- =====================================================================
-- BEGIN;
--
-- WITH ranked AS (
--     SELECT
--         id,
--         ROW_NUMBER() OVER (
--             PARTITION BY title, created_by, assignee
--             ORDER BY submitted_at DESC
--         ) AS recency_rank
--     FROM tasks
--     WHERE state IN ('submitted', 'working')
-- )
-- UPDATE tasks t
-- SET state = 'canceled',
--     canceled_at = now()
-- FROM ranked r
-- WHERE t.id = r.id
--   AND r.recency_rank > 1;
--
-- -- Quick audit after the cancel
-- SELECT count(*) AS pending_after_cleanup
-- FROM tasks
-- WHERE state IN ('submitted', 'working');
--
-- COMMIT;
