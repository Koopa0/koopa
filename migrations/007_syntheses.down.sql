-- Reverse of 007_syntheses.up.sql. Drops the table (and its indexes
-- via CASCADE) cleanly. Since syntheses is an additive historical log
-- with no FK from any other table pointing at it, dropping is safe.

DROP TABLE IF EXISTS syntheses;
