-- project_aliases had a live MCP resolver step (callerIdentity slug-resolution)
-- but no writer at all — no admin path, no github-sync, no seed — so the table
-- was always empty and the alias branch always fell through to title
-- resolution. Drop the unused scaffolding; reintroduce it with a real
-- populate path (github sync or admin) if fuzzy project aliasing is ever wanted.
DROP TABLE IF EXISTS project_aliases;
