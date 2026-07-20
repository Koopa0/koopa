-- Bind a Koopa publication snapshot to its authoring source without making
-- the Vault a runtime dependency. Existing rows remain nullable because the
-- pre-003 database has no evidence from which these coordinates can be
-- reconstructed safely.
ALTER TABLE contents
    ADD COLUMN source_vault_path TEXT,
    ADD COLUMN source_git_blob_sha TEXT;

ALTER TABLE contents
    ADD CONSTRAINT chk_content_source_pair CHECK (
        (source_vault_path IS NULL) = (source_git_blob_sha IS NULL)
    ),
    ADD CONSTRAINT chk_content_source_vault_path CHECK (
        source_vault_path IS NULL OR (
            btrim(source_vault_path) <> ''
            AND source_vault_path = btrim(source_vault_path)
            AND source_vault_path !~ '^/'
            AND source_vault_path !~ '\\'
            AND source_vault_path NOT LIKE '%//%'
            AND source_vault_path !~ '[[:cntrl:]]'
            AND source_vault_path !~ '(^|/)(\.|\.\.)(/|$)'
            AND source_vault_path !~ '(^|/)$'
            AND source_vault_path ~ '\.md$'
            AND lower(source_vault_path) !~ '(^|/)diary(/|$)'
        )
    ),
    ADD CONSTRAINT chk_content_source_git_blob_sha CHECK (
        source_git_blob_sha IS NULL OR
        source_git_blob_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'
    );

COMMENT ON COLUMN contents.source_vault_path IS
    'Declared Vault-relative Markdown source path for this publication snapshot. '
    'Koopa records the coordinate but never reads the Vault at runtime. Diary paths '
    'are rejected at ingress because Diary is private and never publishable.';
COMMENT ON COLUMN contents.source_git_blob_sha IS
    'Declared Git blob object ID for source_vault_path at submission time (40-char SHA-1 '
    'or 64-char SHA-256). This is provenance, not proof that Koopa fetched or verified the blob.';

-- Supersede lifecycle prose frozen in 001: direct Admin authoring is retired.
-- Existing unbound rows remain operable for recovery but cannot enter review
-- or publication; all new publication snapshots arrive through MCP with a
-- complete source pair and only the owner can publish them.
COMMENT ON TABLE contents IS
    'Publication snapshots submitted from Vault for owner review and public display. '
    'Koopa is not an authoring source and never reads or writes Vault at runtime. '
    'Pre-003 source-unbound rows are legacy recovery data and cannot enter review or publication.';
COMMENT ON COLUMN contents.status IS
    'Editorial lifecycle for source-bound snapshots: review -> published or changes_requested; '
    'revise_content returns changes_requested to review with a new source blob SHA. '
    'Only Admin HTTP publishes. Legacy unbound rows cannot enter review or publication.';
COMMENT ON COLUMN contents.created_by IS
    'Submitting agent identity for source-bound snapshots. NULL is retained only on legacy owner-authored rows.';
