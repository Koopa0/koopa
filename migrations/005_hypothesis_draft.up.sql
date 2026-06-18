-- 005: hypothesis 'draft' state.
--
-- Agent-created hypotheses land in 'draft', an inert pre-endorsement state
-- ahead of the existing unverified → verified | invalidated | archived
-- machine. Admin-created hypotheses continue to land in 'unverified'
-- (creating in admin IS the endorsement).
--
-- ALTER TYPE ... ADD VALUE runs inside the migration's implicit transaction
-- (PostgreSQL 12+ allows this), but the new value must not be used as an
-- enum datum in the same transaction. The rebuilt CHECK below therefore
-- compares state::text against string literals — semantically identical,
-- and it never instantiates the new enum value.
ALTER TYPE hypothesis_state ADD VALUE 'draft' BEFORE 'unverified';

-- Drafts carry no resolution evidence — exempt them from the evidence
-- requirement alongside unverified/archived.
ALTER TABLE learning_hypotheses
    DROP CONSTRAINT chk_learning_hypothesis_resolution;
ALTER TABLE learning_hypotheses
    ADD CONSTRAINT chk_learning_hypothesis_resolution
        CHECK (
            state::text IN ('draft', 'unverified', 'archived')
            OR resolved_by_attempt_id IS NOT NULL
            OR resolved_by_observation_id IS NOT NULL
            OR (resolution_summary IS NOT NULL AND btrim(resolution_summary) <> '')
        );

COMMENT ON COLUMN learning_hypotheses.state IS
    'Lifecycle: draft → unverified → verified | invalidated → archived. '
    'draft is the agent-created pre-endorsement state, inert by definition: '
    'it feeds no dashboard, counts toward no progress, and never appears in '
    'brief(morning), the Today aggregate, or any default listing — visible '
    'only in the admin hypotheses list (the triage surface). draft leaves '
    'draft only via owner endorsement in admin (draft → unverified) or '
    'draft-only DELETE. Admin-created rows land directly in unverified.';
