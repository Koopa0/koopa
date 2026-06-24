CREATE TABLE project_aliases (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alias      TEXT NOT NULL,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_project_aliases_lower_alias ON project_aliases (LOWER(alias));

COMMENT ON TABLE project_aliases IS 'Maps variant project names to canonical project. Used by activity event and MCP search to resolve fuzzy project references.';
COMMENT ON COLUMN project_aliases.alias IS 'Variant name (e.g. repo name, external title variant). Case-insensitive unique — "Koopa0.dev" and "koopa0.dev" are the same alias.';
COMMENT ON COLUMN project_aliases.project_id IS 'References canonical project. CASCADE — aliases meaningless without project.';
COMMENT ON COLUMN project_aliases.source IS 'Where this alias was discovered (e.g. github, manual).';
