-- Reverse of 001_initial.up.sql (coordination rebuild schema)

-- syntheses table was removed in the coordination rebuild; nothing to drop.

-- Bookmarks split out of contents polymorphism
DROP TABLE IF EXISTS bookmark_tags;
DROP TABLE IF EXISTS bookmark_topics;
DROP TABLE IF EXISTS bookmarks;

-- Learning plans (depends on plans, items, attempts, agents)
DROP TABLE IF EXISTS learning_plan_entries;
DROP TABLE IF EXISTS learning_plans;

-- Agent schedule history (no FK, but drop before agents for tidiness)
DROP TABLE IF EXISTS agent_schedule_runs;

-- Learning analytics + spaced repetition
-- review_cards/review_logs must drop before items (FK dependency)
DROP TABLE IF EXISTS learning_target_relations;
DROP TABLE IF EXISTS learning_attempt_observations;
DROP TABLE IF EXISTS learning_attempts;
DROP TABLE IF EXISTS learning_sessions;
DROP TABLE IF EXISTS learning_target_concepts;
DROP TABLE IF EXISTS review_logs;
DROP TABLE IF EXISTS review_cards;
DROP TABLE IF EXISTS learning_targets;
DROP TABLE IF EXISTS concepts;

DROP TABLE IF EXISTS drift_check_runs;

-- Coordination layer: artifacts → messages → tasks (coordination) → hypotheses
DROP TABLE IF EXISTS hypotheses;
DROP TABLE IF EXISTS artifacts;
DROP TABLE IF EXISTS task_messages;
DROP TABLE IF EXISTS tasks;

DROP TABLE IF EXISTS project_aliases;
DROP TABLE IF EXISTS event_tags;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS obsidian_note_links;
DROP TABLE IF EXISTS obsidian_note_tags;
DROP TABLE IF EXISTS obsidian_notes;
DROP TABLE IF EXISTS sync_sources;

-- Personal GTD layer
DROP TABLE IF EXISTS daily_plan_items;
DROP TABLE IF EXISTS todo_skips;
DROP TABLE IF EXISTS todos;
DROP TABLE IF EXISTS agent_notes;

DROP TABLE IF EXISTS flow_runs;
DROP TABLE IF EXISTS topic_monitors;
DROP TABLE IF EXISTS feed_entries;
DROP TABLE IF EXISTS feed_topics;
DROP TABLE IF EXISTS feeds;
DROP TABLE IF EXISTS editorial_queue;
DROP TABLE IF EXISTS content_tags;
DROP TABLE IF EXISTS content_topics;
DROP TABLE IF EXISTS contents;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS milestones;
DROP TABLE IF EXISTS goals;
DROP TABLE IF EXISTS areas;
DROP TABLE IF EXISTS tag_aliases;
DROP TABLE IF EXISTS tags;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS topics;
DROP TABLE IF EXISTS agents;

DROP TYPE IF EXISTS event_type;
DROP TYPE IF EXISTS hypothesis_state;
DROP TYPE IF EXISTS message_role;
DROP TYPE IF EXISTS task_state;
DROP TYPE IF EXISTS agent_note_kind;
DROP TYPE IF EXISTS agent_status;
DROP TYPE IF EXISTS todo_state;
DROP TYPE IF EXISTS project_status;
DROP TYPE IF EXISTS goal_status;
DROP TYPE IF EXISTS flow_status;
DROP TYPE IF EXISTS feed_entry_status;
DROP TYPE IF EXISTS review_status;
DROP TYPE IF EXISTS review_level;
DROP TYPE IF EXISTS source_type;
DROP TYPE IF EXISTS content_status;
DROP TYPE IF EXISTS content_type;

DROP EXTENSION IF EXISTS vector;
