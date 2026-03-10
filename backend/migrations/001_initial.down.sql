DROP TABLE IF EXISTS flow_runs;
DROP TABLE IF EXISTS tracking_topics;
DROP TABLE IF EXISTS collected_data;
DROP TABLE IF EXISTS feeds;
DROP TABLE IF EXISTS review_queue;
DROP TABLE IF EXISTS content_topics;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS contents;
DROP TABLE IF EXISTS topics;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;

DROP TYPE IF EXISTS project_status;
DROP TYPE IF EXISTS collected_status;
DROP TYPE IF EXISTS review_status;
DROP TYPE IF EXISTS review_level;
DROP TYPE IF EXISTS source_type;
DROP TYPE IF EXISTS content_status;
DROP TYPE IF EXISTS flow_status;
DROP TYPE IF EXISTS content_type;

DROP EXTENSION IF EXISTS vector;
