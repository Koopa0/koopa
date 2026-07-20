-- Rollback removes the columns introduced by 003. As with the repository's
-- earlier down migrations, operators must restore data from backup rather than
-- expect a schema rollback to preserve values from removed columns.
ALTER TABLE contents
    DROP CONSTRAINT IF EXISTS chk_content_source_git_blob_sha,
    DROP CONSTRAINT IF EXISTS chk_content_source_vault_path,
    DROP CONSTRAINT IF EXISTS chk_content_source_pair,
    DROP COLUMN IF EXISTS source_git_blob_sha,
    DROP COLUMN IF EXISTS source_vault_path;

-- Restore the 001 comments together with the 001 schema shape.
COMMENT ON TABLE contents IS $comment$First-party publishable knowledge layer. Five content types (article, essay, build-log, til, digest) share one editorial lifecycle: draft → published, with a review handoff for agent-proposed content. The owner publishes a draft directly (admin HTTP); an agent instead pushes a finished draft into review (propose_content), and from the admin review queue the owner publishes OR sends it back (status changes_requested + review_note) for the authoring agent to revise (revise_content) back into review. published status and published_at are tied by chk_content_publication; is_public requires published by chk_content_public_requires_published.$comment$;
COMMENT ON COLUMN contents.status IS $comment$Lifecycle: draft → published directly (the owner publishing their own finished work), or draft → review → published for agent-proposed content; changes_requested → review is the agent revision loop. review = an agent proposal (propose_content) awaiting the owner's publish-or-send-back decision. changes_requested = the owner sent it back for revision, reason in review_note; the authoring agent addresses it with revise_content, which returns the row to review. published = live; archived = soft delete. Publishing (draft or review → published) and send-back are human-admin only (admin HTTP); agents never publish — propose_content/revise_content only ever land a row in review.$comment$;
COMMENT ON COLUMN contents.created_by IS $comment$Proposing agent for agent-pushed content (references agents(name), e.g. hermes pushing a finished draft via the propose_content MCP tool). NULL for owner/admin-authored content created through the admin UI. ON DELETE RESTRICT — a registered agent that has proposed content cannot be removed while its proposals exist.$comment$;
