-- Reverse 003_tasks_acknowledged.up.sql.
--
-- approved: drop column
-- This is a down-migration. The columns it removes were added by the
-- corresponding up-migration; rolling back must drop them. There is no
-- safer alternative for a down-migration.

DROP TRIGGER IF EXISTS trg_tasks_audit ON tasks;

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
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tasks_audit
    AFTER INSERT OR UPDATE OF state ON tasks
    FOR EACH ROW EXECUTE FUNCTION audit_tasks();

-- Acknowledgement audit rows have no v002 meaning. Remove them before
-- re-adding the narrower CHECK so constraint validation does not
-- reject existing data. The audit feed loses ack history on downgrade
-- (honest, since the feature itself is being reversed); the task rows
-- themselves keep their other columns until the column-removal
-- statements below take effect.
DELETE FROM activity_events WHERE change_kind = 'acknowledged';

ALTER TABLE activity_events DROP CONSTRAINT activity_events_change_kind_check;
ALTER TABLE activity_events ADD CONSTRAINT activity_events_change_kind_check
    CHECK (change_kind IN (
        'created', 'updated', 'state_changed', 'published',
        'completed', 'archived'
    ));

DROP INDEX IF EXISTS idx_tasks_awaiting_approval;

ALTER TABLE tasks DROP CONSTRAINT IF EXISTS chk_tasks_acknowledged_pair;
ALTER TABLE tasks DROP COLUMN IF EXISTS acknowledged_by;
ALTER TABLE tasks DROP COLUMN IF EXISTS acknowledged_at;
