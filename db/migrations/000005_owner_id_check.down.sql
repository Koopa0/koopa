ALTER TABLE sessions ALTER COLUMN owner_id SET DEFAULT '';
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_owner_id_not_empty;
