-- Reverse of 001_initial.up.sql (schema v2)

DROP VIEW IF EXISTS tool_daily_trend;
DROP VIEW IF EXISTS tool_usage_summary;

DROP TABLE IF EXISTS reconcile_runs;
DROP TABLE IF EXISTS tool_call_logs;
DROP TABLE IF EXISTS review_logs;
DROP TABLE IF EXISTS review_cards;
DROP TABLE IF EXISTS insights;
DROP TABLE IF EXISTS journal;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS project_aliases;
DROP TABLE IF EXISTS event_tags;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS note_links;
DROP TABLE IF EXISTS note_tags;
DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS sources;
DROP TABLE IF EXISTS task_skips;
DROP TABLE IF EXISTS tasks;
DROP TABLE IF EXISTS flow_runs;
DROP TABLE IF EXISTS topic_monitors;
DROP TABLE IF EXISTS feed_entries;
DROP TABLE IF EXISTS feed_topics;
DROP TABLE IF EXISTS feeds;
DROP TABLE IF EXISTS review_queue;
DROP TABLE IF EXISTS content_tags;
DROP TABLE IF EXISTS content_topics;
DROP TABLE IF EXISTS contents;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS goals;
DROP TABLE IF EXISTS tag_aliases;
DROP TABLE IF EXISTS tags;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS topics;
DROP TABLE IF EXISTS participant;
DROP TABLE IF EXISTS platform;

DROP TYPE IF EXISTS event_type;
DROP TYPE IF EXISTS task_status;
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
