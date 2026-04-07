-- Reverse seed data (delete in dependency order)
DELETE FROM participant_schedules;
DELETE FROM feed_topics;
DELETE FROM feeds;
DELETE FROM tags;
DELETE FROM topics;
-- platform and participant seed data is in 001, not here
