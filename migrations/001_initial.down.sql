-- Reverse of 001_initial.up.sql
-- Drop order: triggers → functions → deferred FKs → tables (reverse FK order) → types → extensions

-- ============================================================
-- 1. Triggers (drop before their parent tables and functions)
-- ============================================================

DROP TRIGGER IF EXISTS trg_learning_sessions_audit ON learning_sessions;
DROP TRIGGER IF EXISTS trg_learning_plan_entries_audit ON learning_plan_entries;
DROP TRIGGER IF EXISTS trg_learning_hypotheses_audit ON learning_hypotheses;
DROP TRIGGER IF EXISTS trg_tasks_audit ON tasks;
DROP TRIGGER IF EXISTS trg_learning_attempts_audit ON learning_attempts;
DROP TRIGGER IF EXISTS trg_bookmarks_audit ON bookmarks;
DROP TRIGGER IF EXISTS trg_contents_audit ON contents;
DROP TRIGGER IF EXISTS trg_projects_audit ON projects;
DROP TRIGGER IF EXISTS trg_milestones_audit ON milestones;
DROP TRIGGER IF EXISTS trg_goals_audit ON goals;
DROP TRIGGER IF EXISTS trg_todos_audit ON todos;
DROP TRIGGER IF EXISTS trg_learning_target_relations_domain ON learning_target_relations;
DROP TRIGGER IF EXISTS trg_concepts_acyclicity ON concepts;
DROP TRIGGER IF EXISTS trg_concepts_parent_domain ON concepts;
DROP TRIGGER IF EXISTS trg_tasks_completion_requires_outputs ON tasks;

-- ============================================================
-- 2. Functions
-- ============================================================

DROP FUNCTION IF EXISTS audit_learning_sessions();
DROP FUNCTION IF EXISTS audit_learning_plan_entries();
DROP FUNCTION IF EXISTS audit_learning_hypotheses();
DROP FUNCTION IF EXISTS audit_tasks();
DROP FUNCTION IF EXISTS audit_learning_attempts();
DROP FUNCTION IF EXISTS audit_bookmarks();
DROP FUNCTION IF EXISTS audit_contents();
DROP FUNCTION IF EXISTS audit_projects();
DROP FUNCTION IF EXISTS audit_milestones();
DROP FUNCTION IF EXISTS audit_goals();
DROP FUNCTION IF EXISTS audit_todos();
DROP FUNCTION IF EXISTS current_actor();
DROP FUNCTION IF EXISTS enforce_learning_target_relation_domain();
DROP FUNCTION IF EXISTS enforce_concept_acyclicity();
DROP FUNCTION IF EXISTS enforce_concept_parent_domain();
DROP FUNCTION IF EXISTS enforce_task_completion_outputs();

-- ============================================================
-- 3. Deferred foreign keys
--
-- (The previous feed_entries → bookmarks deferred FK was removed
-- entry when the feed→bookmark curation path was dropped.)
-- ============================================================

-- ============================================================
-- 4. Tables (reverse creation order, respecting FK dependencies)
-- ============================================================

-- Bookmarks + junctions
DROP TABLE IF EXISTS bookmark_tags;
DROP TABLE IF EXISTS bookmark_topics;
DROP TABLE IF EXISTS bookmarks;

-- Learning plans
DROP TABLE IF EXISTS learning_plan_entries;
DROP TABLE IF EXISTS learning_plans;

-- Hypotheses (FKs into learning_attempts and observations)
DROP TABLE IF EXISTS learning_hypotheses;

-- Learning analytics (reverse creation order)
DROP TABLE IF EXISTS learning_target_relations;
DROP TABLE IF EXISTS learning_attempt_observations;
DROP TABLE IF EXISTS learning_attempts;
DROP TABLE IF EXISTS learning_sessions;
-- Note junctions (FKs into notes, learning_targets, contents, concepts)
DROP TABLE IF EXISTS note_concepts;
DROP TABLE IF EXISTS learning_target_contents;
DROP TABLE IF EXISTS learning_target_notes;
DROP TABLE IF EXISTS learning_target_concepts;
DROP TABLE IF EXISTS review_logs;
DROP TABLE IF EXISTS review_cards;
DROP TABLE IF EXISTS learning_targets;
DROP TABLE IF EXISTS content_concepts;
DROP TABLE IF EXISTS concepts;
DROP TABLE IF EXISTS learning_domains;

-- Coordination layer
DROP TABLE IF EXISTS artifacts;
DROP TABLE IF EXISTS task_messages;
DROP TABLE IF EXISTS tasks;

-- Project aliases
DROP TABLE IF EXISTS project_aliases;

-- Activity events
DROP TABLE IF EXISTS activity_events;

-- Personal GTD layer
DROP TABLE IF EXISTS todo_skips;
DROP TABLE IF EXISTS daily_plan_items;
DROP TABLE IF EXISTS agent_notes;
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

-- Notes (FK target of note-junctions — dropped above)
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
DROP TYPE IF EXISTS hypothesis_state;
DROP TYPE IF EXISTS message_role;
DROP TYPE IF EXISTS task_state;
DROP TYPE IF EXISTS agent_note_kind;
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
