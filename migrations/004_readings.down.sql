-- Remove the readings shelf + diary. reading_reflections first — it FKs
-- onto readings. Both tables are private admin-only data: dropping them
-- destroys the reading diary irreversibly, so back up before migrating down.
DROP TABLE IF EXISTS reading_reflections;
DROP TABLE IF EXISTS readings;
