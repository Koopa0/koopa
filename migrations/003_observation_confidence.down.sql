-- approved: drop column
--
-- WARNING: dropping the confidence column loses every low-confidence
-- observation written after migration 003 was applied. Before rolling back
-- in any environment that has accumulated real data, copy the affected
-- rows out:
--
--   COPY (SELECT * FROM attempt_observations WHERE confidence = 'low')
--     TO '/tmp/low_confidence_observations.csv' CSV HEADER;
--
-- The pre-003 schema has no place to land these rows on re-up, so the
-- export is one-way recovery only — it exists so a future operator can
-- audit what was lost, not so it can be replayed.

DROP INDEX IF EXISTS idx_attempt_observations_high_confidence;

ALTER TABLE attempt_observations DROP COLUMN confidence;
