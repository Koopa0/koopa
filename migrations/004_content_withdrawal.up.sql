-- Durable withdrawal keeps status='published' as the historical publication
-- fact. Current exposure is represented by is_public, with a required reason
-- and timestamp whenever a published snapshot is withdrawn.

ALTER TABLE contents
    ADD COLUMN withdrawn_at TIMESTAMPTZ,
    ADD COLUMN withdrawal_reason TEXT;

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
    ELSIF NEW.status = 'published' AND OLD.is_public AND NOT NEW.is_public THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, entity_slug, change_kind, project_id, area_id, actor, payload, occurred_at)
        VALUES ('content', NEW.id, NEW.title, NEW.slug, 'state_changed', NEW.project_id,
                (SELECT area_id FROM projects WHERE id = NEW.project_id), current_actor(),
                jsonb_build_object(
                    'transition', 'withdrawn',
                    'from', 'public',
                    'to', 'withdrawn',
                    'reason', NEW.withdrawal_reason,
                    'withdrawn_at', NEW.withdrawn_at,
                    'published_at', NEW.published_at,
                    'source_vault_path', NEW.source_vault_path,
                    'source_git_blob_sha', NEW.source_git_blob_sha),
                NEW.withdrawn_at);
    ELSIF NEW.status = 'published' AND NOT OLD.is_public AND NEW.is_public THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, entity_slug, change_kind, project_id, area_id, actor, payload)
        VALUES ('content', NEW.id, NEW.title, NEW.slug, 'state_changed', NEW.project_id,
                (SELECT area_id FROM projects WHERE id = NEW.project_id), current_actor(),
                jsonb_build_object(
                    'transition', 'restored',
                    'from', 'withdrawn',
                    'to', 'public',
                    'reason', OLD.withdrawal_reason,
                    'withdrawn_at', OLD.withdrawn_at,
                    'published_at', NEW.published_at,
                    'source_vault_path', NEW.source_vault_path,
                    'source_git_blob_sha', NEW.source_git_blob_sha));
    ELSIF NEW.status = 'published' AND NOT NEW.is_public
          AND OLD.withdrawn_at IS NULL AND NEW.withdrawn_at IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM activity_events
              WHERE entity_type = 'content' AND entity_id = NEW.id
                AND payload->>'transition' = 'withdrawn'
                AND payload->>'from' = 'legacy_private'
          ) THEN
        -- One-time conversion of rows hidden by the retired generic visibility
        -- switch. The explicit reason makes the uncertainty visible instead of
        -- inventing a historical owner explanation.
        INSERT INTO activity_events (entity_type, entity_id, entity_title, entity_slug, change_kind, project_id, area_id, actor, payload, occurred_at)
        VALUES ('content', NEW.id, NEW.title, NEW.slug, 'state_changed', NEW.project_id,
                (SELECT area_id FROM projects WHERE id = NEW.project_id), current_actor(),
                jsonb_build_object(
                    'transition', 'withdrawn',
                    'from', 'legacy_private',
                    'to', 'withdrawn',
                    'reason', NEW.withdrawal_reason,
                    'withdrawn_at', NEW.withdrawn_at,
                    'published_at', NEW.published_at,
                    'source_vault_path', NEW.source_vault_path,
                    'source_git_blob_sha', NEW.source_git_blob_sha),
                NEW.withdrawn_at);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER trg_contents_audit ON contents;
CREATE TRIGGER trg_contents_audit
    AFTER INSERT OR UPDATE OF status, is_public, withdrawn_at, withdrawal_reason ON contents
    FOR EACH ROW EXECUTE FUNCTION audit_contents();

UPDATE contents
SET withdrawn_at = updated_at,
    withdrawal_reason = 'Migrated from the retired private-visibility control'
WHERE status = 'published' AND NOT is_public;

-- Published is a historical fact and the row is an immutable Vault snapshot.
-- Only current exposure, its paired withdrawal metadata, and updated_at may
-- change after publication. search_vector is generated from immutable authored
-- fields, so it is excluded from the record comparison itself.
CREATE FUNCTION guard_content_withdrawal_metadata() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status = 'published'
       AND (to_jsonb(NEW) - ARRAY['is_public', 'withdrawn_at', 'withdrawal_reason', 'updated_at', 'search_vector']::TEXT[])
           IS DISTINCT FROM
           (to_jsonb(OLD) - ARRAY['is_public', 'withdrawn_at', 'withdrawal_reason', 'updated_at', 'search_vector']::TEXT[]) THEN
        RAISE EXCEPTION 'published snapshots are immutable'
            USING ERRCODE = '23514';
    ELSIF NEW.is_public IS NOT DISTINCT FROM OLD.is_public
       AND (NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at
            OR NEW.withdrawal_reason IS DISTINCT FROM OLD.withdrawal_reason) THEN
        RAISE EXCEPTION 'withdrawal metadata may change only through withdraw or restore'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_contents_withdrawal_metadata_guard
    BEFORE UPDATE ON contents
    FOR EACH ROW EXECUTE FUNCTION guard_content_withdrawal_metadata();

ALTER TABLE contents
    ADD CONSTRAINT chk_content_withdrawal_fields_pair
        CHECK ((withdrawn_at IS NULL) = (withdrawal_reason IS NULL)),
    ADD CONSTRAINT chk_content_withdrawal_state
        CHECK (
            (status = 'published' AND NOT is_public) = (withdrawn_at IS NOT NULL)
        ),
    ADD CONSTRAINT chk_content_withdrawal_reason
        CHECK (
            withdrawal_reason IS NULL OR
            (btrim(withdrawal_reason) <> '' AND char_length(withdrawal_reason) <= 500)
        );

COMMENT ON COLUMN contents.withdrawn_at IS
    'When Koopa stopped serving this historically published snapshot. Present exactly when status=published and is_public=false.';
COMMENT ON COLUMN contents.withdrawal_reason IS
    'Owner-supplied reason for the current withdrawal. Admin-only; the trigger copies it into the durable activity receipt before restore clears it.';
COMMENT ON COLUMN contents.is_public IS
    'Current public exposure. For status=published: true=served, false=withdrawn with reason/timestamp. Other statuses are private by chk_content_public_requires_published.';
COMMENT ON COLUMN contents.status IS
    'Editorial lifecycle and publication history. published remains true after withdrawal; current exposure is is_public. archived is only for never-published work.';
