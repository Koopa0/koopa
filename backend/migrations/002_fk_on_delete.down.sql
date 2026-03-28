-- Revert to original constraints (no ON DELETE action = RESTRICT/NO ACTION)
ALTER TABLE tag_aliases DROP CONSTRAINT IF EXISTS tag_aliases_tag_id_fkey;
ALTER TABLE tag_aliases ADD CONSTRAINT tag_aliases_tag_id_fkey
    FOREIGN KEY (tag_id) REFERENCES tags(id);

ALTER TABLE tags DROP CONSTRAINT IF EXISTS tags_parent_id_fkey;
ALTER TABLE tags ADD CONSTRAINT tags_parent_id_fkey
    FOREIGN KEY (parent_id) REFERENCES tags(id);
