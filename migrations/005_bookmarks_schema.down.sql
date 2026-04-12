-- Reverse of 005_bookmarks_schema.up.sql.
-- Safe to run: this migration never wrote data to bookmarks or its
-- junctions. If 006 (backfill) has run, prefer rolling 006 back first.

DROP TABLE IF EXISTS bookmark_tags;
DROP TABLE IF EXISTS bookmark_topics;
DROP TABLE IF EXISTS bookmarks;
