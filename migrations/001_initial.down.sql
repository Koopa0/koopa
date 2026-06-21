-- Reverse of 001_initial.up.sql
-- Drop order: triggers → functions → deferred FKs → tables (reverse FK order) → types → extensions

-- ============================================================
-- 1. Triggers (drop before their parent tables and functions)
-- ============================================================

DROP TRIGGER IF EXISTS trg_contents_audit ON contents;
DROP TRIGGER IF EXISTS trg_projects_audit ON projects;
DROP TRIGGER IF EXISTS trg_milestones_audit ON milestones;
DROP TRIGGER IF EXISTS trg_goals_audit ON goals;
DROP TRIGGER IF EXISTS trg_todos_audit ON todos;

-- ============================================================
-- 2. Functions
-- ============================================================

DROP FUNCTION IF EXISTS audit_contents();
DROP FUNCTION IF EXISTS audit_projects();
DROP FUNCTION IF EXISTS audit_milestones();
DROP FUNCTION IF EXISTS audit_goals();
DROP FUNCTION IF EXISTS audit_todos();
DROP FUNCTION IF EXISTS current_actor();

-- ============================================================
-- 3. Deferred foreign keys
--
-- (The previous feed_entries → bookmarks deferred FK was removed
-- entry when the feed→bookmark curation path was dropped.)
-- ============================================================

-- ============================================================
-- 4. Tables (reverse creation order, respecting FK dependencies)
-- ============================================================

-- Songs + readings shelves (private; reflections FK their parent — drop first)
DROP TABLE IF EXISTS song_reflections;
DROP TABLE IF EXISTS songs;
DROP TABLE IF EXISTS reading_reflections;
DROP TABLE IF EXISTS readings;

-- Project aliases
DROP TABLE IF EXISTS project_aliases;

-- Activity events
DROP TABLE IF EXISTS activity_events;

-- Personal GTD layer
DROP TABLE IF EXISTS todo_skips;
DROP TABLE IF EXISTS daily_plan_items;
DROP TABLE IF EXISTS todos;

-- Process runs
DROP TABLE IF EXISTS process_runs;

-- Feeds + entries + junctions
DROP TABLE IF EXISTS feed_entries;
DROP TABLE IF EXISTS feed_topics;
DROP TABLE IF EXISTS feeds;

-- Content junctions
DROP TABLE IF EXISTS content_tags;
DROP TABLE IF EXISTS content_topics;

-- Notes
DROP TABLE IF EXISTS notes;

-- Contents
DROP TABLE IF EXISTS contents;

-- Projects + profiles
DROP TABLE IF EXISTS project_profiles;
DROP TABLE IF EXISTS projects;

-- Milestones (FK to goals)
DROP TABLE IF EXISTS milestones;

-- Goals (FK to areas)
DROP TABLE IF EXISTS goals;

-- Areas
DROP TABLE IF EXISTS areas;

-- Tag aliases (FK to tags)
DROP TABLE IF EXISTS tag_aliases;

-- Tags
DROP TABLE IF EXISTS tags;

-- Topics
DROP TABLE IF EXISTS topics;

-- Auth
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;

-- Agents (FK target for many tables, must be last)
DROP TABLE IF EXISTS agents;

-- ============================================================
-- 5. Enum types
-- ============================================================

DROP TYPE IF EXISTS note_maturity;
DROP TYPE IF EXISTS note_kind;
DROP TYPE IF EXISTS agent_status;
DROP TYPE IF EXISTS todo_state;
DROP TYPE IF EXISTS project_status;
DROP TYPE IF EXISTS goal_status;
DROP TYPE IF EXISTS feed_entry_status;
DROP TYPE IF EXISTS content_status;
DROP TYPE IF EXISTS content_type;

-- ============================================================
-- 6. Extensions
-- ============================================================

DROP EXTENSION IF EXISTS vector;
