-- Confidence column on attempt_observations.
--
-- Background: prior to this migration, low-confidence observations (the
-- coach has a hunch but the signal isn't directly evidenced by the attempt
-- outcome) were filtered at the MCP layer and returned to the caller as
-- "pending" — never persisted, never confirmable, silently dropped on the
-- next conversation turn. Audit found this lost data without any way to
-- detect the loss.
--
-- New model: confidence is an attribute of the observation, not a gate.
-- Every observation persists. Dashboard reads default to high-confidence
-- only (preserving the previous user-facing behaviour) but low-confidence
-- observations remain in the database for historical analysis and can be
-- surfaced via confidence_filter='all' on mastery and weakness views.
--
-- The < N observations → "developing" floor in deriveMasteryStage looks
-- at the FILTERED count, not the total — this is what makes confidence
-- semantically a label and not a half-gate. Without that property a single
-- low-confidence observation could "unlock" a stage from no-data into
-- struggling/solid, which would re-create the hidden-decision problem we
-- just removed.

ALTER TABLE attempt_observations
    ADD COLUMN confidence TEXT NOT NULL DEFAULT 'high'
        CHECK (confidence IN ('high', 'low'));

COMMENT ON COLUMN attempt_observations.confidence IS
    'high (default): signal directly evidenced by the attempt outcome — '
    'user said "I forgot how X works" or repeatedly failed at X. '
    'low: coach inferred the signal from indirect evidence — '
    'user struggled with the problem and coach suspects X is the missing skill. '
    'Both persist. Dashboard mastery and weakness views default to high only; '
    'pass confidence_filter=all to include low-confidence observations.';

-- Partial index for the dominant read pattern (mastery / weakness aggregations
-- filtered to high confidence). Skipping low rows reduces the index size when
-- low observations grow over time without paying for unused tuples in the
-- common case.
CREATE INDEX idx_attempt_observations_high_confidence
    ON attempt_observations (concept_id, created_at DESC)
    WHERE confidence = 'high';
