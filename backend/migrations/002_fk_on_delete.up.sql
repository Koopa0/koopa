-- tags.parent_id: orphan tags become root when parent is deleted
ALTER TABLE tags DROP CONSTRAINT IF EXISTS tags_parent_id_fkey;
ALTER TABLE tags ADD CONSTRAINT tags_parent_id_fkey
    FOREIGN KEY (parent_id) REFERENCES tags(id) ON DELETE SET NULL;

-- tag_aliases.tag_id: aliases are meaningless without the tag
ALTER TABLE tag_aliases DROP CONSTRAINT IF EXISTS tag_aliases_tag_id_fkey;
ALTER TABLE tag_aliases ADD CONSTRAINT tag_aliases_tag_id_fkey
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE;
