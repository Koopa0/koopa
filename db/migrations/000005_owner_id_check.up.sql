-- Backfill empty owner_id before adding constraint.
-- Sessions created before ownership was enforced may have owner_id = ''.
UPDATE sessions SET owner_id = 'anonymous' WHERE owner_id = '';

-- Prevent empty owner_id in sessions (enforces NOT NULL + non-empty).
ALTER TABLE sessions ADD CONSTRAINT sessions_owner_id_not_empty CHECK (owner_id != '');
ALTER TABLE sessions ALTER COLUMN owner_id DROP DEFAULT;
