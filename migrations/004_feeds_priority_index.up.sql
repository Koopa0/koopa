-- Improve morning_context RSS highlights query performance.
-- The HighPriorityRecent query joins feeds + feed_entries with filters on
-- feeds.priority and feed_entries.status + collected_at. Without these indexes,
-- PostgreSQL performs full table scans on both tables.

CREATE INDEX idx_feeds_high_priority ON feeds(id) WHERE priority = 'high';
CREATE INDEX idx_feed_entries_unread_recent ON feed_entries(feed_id, collected_at DESC) WHERE status = 'unread';
