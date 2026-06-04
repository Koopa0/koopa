-- Reverse 004_report_lane.up.sql.
--
-- Drop reports first (it references research_assignments via
-- origin_assignment_id), then research_assignments. Both tables and all their
-- data are removed; this is a down-migration and there is no safer alternative.
-- No data backup strategy is needed because the report lane is new in 004 —
-- there is no pre-existing data to preserve.

DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS research_assignments;
