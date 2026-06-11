-- 005 down: remove the 'draft' value by rebuilding hypothesis_state.
--
-- PRECONDITION: zero draft rows. PostgreSQL cannot drop a single enum value,
-- so the type is rebuilt without 'draft' and the column is cast across. The
-- USING cast below fails loudly ("invalid input value for enum") if any row
-- still carries state='draft' — endorse (→ unverified) or delete drafts
-- before migrating down. That failure is the guard, not a bug.
ALTER TABLE learning_hypotheses
    DROP CONSTRAINT chk_learning_hypothesis_resolution;
-- chk_learning_hypothesis_resolved_at's stored expression carries
-- 'verified'::hypothesis_state enum literals; the column-type swap below
-- cannot re-validate it against the rebuilt type ("operator does not
-- exist"). Drop it for the swap and recreate it verbatim (from 001) after.
ALTER TABLE learning_hypotheses
    DROP CONSTRAINT chk_learning_hypothesis_resolved_at;
ALTER TABLE learning_hypotheses
    ALTER COLUMN state DROP DEFAULT;

-- trg_learning_hypotheses_audit is declared AFTER UPDATE OF state, and a
-- column-specific trigger blocks ALTER COLUMN ... TYPE ("cannot alter type
-- of a column used in a trigger definition"). Drop it for the swap and
-- recreate it verbatim (definition from 001) afterwards.
DROP TRIGGER trg_learning_hypotheses_audit ON learning_hypotheses;

CREATE TYPE hypothesis_state_pre_draft AS ENUM (
    'unverified', 'verified', 'invalidated', 'archived'
);
ALTER TABLE learning_hypotheses
    ALTER COLUMN state TYPE hypothesis_state_pre_draft
    USING state::text::hypothesis_state_pre_draft;
DROP TYPE hypothesis_state;
ALTER TYPE hypothesis_state_pre_draft RENAME TO hypothesis_state;

CREATE TRIGGER trg_learning_hypotheses_audit
    AFTER UPDATE OF state ON learning_hypotheses
    FOR EACH ROW
    WHEN (OLD.state IS DISTINCT FROM NEW.state)
    EXECUTE FUNCTION audit_learning_hypotheses();

ALTER TABLE learning_hypotheses
    ALTER COLUMN state SET DEFAULT 'unverified';
ALTER TABLE learning_hypotheses
    ADD CONSTRAINT chk_learning_hypothesis_resolved_at
        CHECK ((state IN ('verified', 'invalidated')) = (resolved_at IS NOT NULL));
ALTER TABLE learning_hypotheses
    ADD CONSTRAINT chk_learning_hypothesis_resolution
        CHECK (
            state IN ('unverified', 'archived')
            OR resolved_by_attempt_id IS NOT NULL
            OR resolved_by_observation_id IS NOT NULL
            OR (resolution_summary IS NOT NULL AND btrim(resolution_summary) <> '')
        );

COMMENT ON COLUMN learning_hypotheses.state IS
    'Lifecycle: unverified → verified | invalidated → archived.';
