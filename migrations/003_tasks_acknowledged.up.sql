-- Approve / awaiting-judgment semantic fix.
--
-- Adds durable acknowledgement to tasks. Until this migration the
-- /approve route only appended a response message and left tasks.state
-- unchanged, so awaiting-approval inboxes had no way to shrink. After
-- this migration acknowledgement is a first-class column pair on tasks
-- and the audit feed records the transition.

-- ---- New ack columns on tasks --------------------------------------

ALTER TABLE tasks
    ADD COLUMN acknowledged_at TIMESTAMPTZ,
    ADD COLUMN acknowledged_by TEXT REFERENCES agents(name) ON DELETE RESTRICT;

COMMENT ON COLUMN tasks.acknowledged_at IS
    'Source-side final acceptance of the current completed result. NULL until '
    'the source agent calls /approve on a completed, unacknowledged task. '
    'A non-NULL value means: this delivery is accepted, the task is closed '
    'for revisions, and the awaiting-judgment inbox should not show it.';
COMMENT ON COLUMN tasks.acknowledged_by IS
    'Agent that acknowledged the task. Must equal tasks.created_by — '
    'enforced at the store layer, not at the schema, because the FK can only '
    'check agents(name) existence. NULL together with acknowledged_at.';

-- Pair invariant: both columns move together, and ack is only meaningful
-- on a completed task. Transitions away from completed (cancel, revision)
-- are blocked by the store while ack is set, so this CHECK doubles as a
-- structural floor.
ALTER TABLE tasks
    ADD CONSTRAINT chk_tasks_acknowledged_pair CHECK (
        (acknowledged_at IS NULL AND acknowledged_by IS NULL)
        OR
        (state = 'completed' AND acknowledged_at IS NOT NULL AND acknowledged_by IS NOT NULL)
    );

-- Awaiting-approval predicate — supports the partial scan used by the
-- AwaitingApproval query and by Today fan-out filters. completed_at is
-- not strictly part of the predicate but every awaiting-approval read
-- orders by it, so a covering ordered partial index is the right shape.
CREATE INDEX idx_tasks_awaiting_approval
    ON tasks (completed_at DESC)
    WHERE state = 'completed' AND acknowledged_at IS NULL;

-- ---- activity_events.change_kind: allow 'acknowledged' --------------

ALTER TABLE activity_events DROP CONSTRAINT activity_events_change_kind_check;
ALTER TABLE activity_events ADD CONSTRAINT activity_events_change_kind_check
    CHECK (change_kind IN (
        'created', 'updated', 'state_changed', 'published',
        'completed', 'archived', 'acknowledged'
    ));

COMMENT ON COLUMN activity_events.change_kind IS
    'Closed set of mutation kinds. created = INSERT. state_changed = enum/status transition. '
    'completed/published/archived = specific terminal transitions worth distinguishing. '
    'acknowledged = source-side final acceptance of a completed task (state stays completed). '
    'updated = generic field change.';

-- ---- audit_tasks trigger: emit acknowledged events ------------------

CREATE OR REPLACE FUNCTION audit_tasks() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
        VALUES ('task', NEW.id, NEW.title, 'created', current_actor(),
                jsonb_build_object('state', NEW.state,
                                   'assignee', NEW.assignee, 'created_by', NEW.created_by));
    ELSIF NEW.state IS DISTINCT FROM OLD.state THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
        VALUES ('task', NEW.id, NEW.title,
                CASE WHEN NEW.state = 'completed' THEN 'completed' ELSE 'state_changed' END,
                current_actor(),
                jsonb_build_object('from', OLD.state, 'to', NEW.state,
                                   'assignee', NEW.assignee, 'created_by', NEW.created_by));
    ELSIF NEW.acknowledged_at IS DISTINCT FROM OLD.acknowledged_at
          AND NEW.acknowledged_at IS NOT NULL THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
        VALUES ('task', NEW.id, NEW.title, 'acknowledged', current_actor(),
                jsonb_build_object('acknowledged_by', NEW.acknowledged_by,
                                   'assignee', NEW.assignee, 'created_by', NEW.created_by));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tasks_audit ON tasks;
CREATE TRIGGER trg_tasks_audit
    AFTER INSERT OR UPDATE OF state, acknowledged_at ON tasks
    FOR EACH ROW EXECUTE FUNCTION audit_tasks();
