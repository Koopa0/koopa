-- A rollback cannot represent an active withdrawal after dropping its reason
-- and timestamp. Refuse data loss; restore the publication first (or restore a
-- backup) before deliberately removing this migration.
-- approved: drop column
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM contents WHERE withdrawn_at IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back migration 004 while withdrawn publications exist';
    END IF;
END;
$$;

ALTER TABLE contents
    DROP CONSTRAINT chk_content_withdrawal_reason,
    DROP CONSTRAINT chk_content_withdrawal_state,
    DROP CONSTRAINT chk_content_withdrawal_fields_pair;

DROP TRIGGER trg_contents_withdrawal_metadata_guard ON contents;
DROP FUNCTION guard_content_withdrawal_metadata();

CREATE OR REPLACE FUNCTION audit_contents() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, entity_slug, change_kind, project_id, area_id, actor, payload)
        VALUES ('content', NEW.id, NEW.title, NEW.slug, 'created', NEW.project_id,
                (SELECT area_id FROM projects WHERE id = NEW.project_id), current_actor(),
                jsonb_build_object('status', NEW.status, 'type', NEW.type));
    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, entity_slug, change_kind, project_id, area_id, actor, payload)
        VALUES ('content', NEW.id, NEW.title, NEW.slug,
                CASE
                    WHEN NEW.status = 'published' THEN 'published'
                    WHEN NEW.status = 'archived'  THEN 'archived'
                    ELSE 'state_changed'
                END,
                NEW.project_id, (SELECT area_id FROM projects WHERE id = NEW.project_id), current_actor(),
                jsonb_build_object('from', OLD.status, 'to', NEW.status));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER trg_contents_audit ON contents;
CREATE TRIGGER trg_contents_audit
    AFTER INSERT OR UPDATE OF status ON contents
    FOR EACH ROW EXECUTE FUNCTION audit_contents();

ALTER TABLE contents
    DROP COLUMN withdrawal_reason,
    DROP COLUMN withdrawn_at;

COMMENT ON COLUMN contents.is_public IS
    'Controls public visibility (private-by-default). When true, status MUST be published.';
COMMENT ON COLUMN contents.status IS
    'Editorial lifecycle for source-bound snapshots: review -> published or changes_requested; '
    'revise_content returns changes_requested to review with a new source blob SHA. '
    'Only Admin HTTP publishes. Legacy unbound rows cannot enter review or publication.';
