-- approved: drop column
-- agent_schedule was a process_runs kind with no producer — agent schedules run
-- in the external Cowork runner, not tracked here — so the kind and its
-- dashboard bucket were always empty. The subsystem column existed only for that
-- kind (never written; the stats queries filter on name, not subsystem). It is a
-- provably-always-NULL dead column, so dropping it loses no data. The feed-crawl
-- scheduler (the live producer of kind='crawl') is untouched.
ALTER TABLE process_runs DROP CONSTRAINT chk_process_runs_subsystem_iff_agent_schedule;
ALTER TABLE process_runs DROP COLUMN subsystem;
ALTER TABLE process_runs DROP CONSTRAINT process_runs_kind_check;
ALTER TABLE process_runs ADD CONSTRAINT process_runs_kind_check CHECK (kind IN ('crawl'));

COMMENT ON TABLE process_runs IS
    'Run-history records for background processes. kind=crawl: internal '
    'crawl/fetch runs such as the RSS feed collector. Kind-specific fields live '
    'in metadata. RETENTION: 90 days for terminal runs; pending/running rows are '
    'operational state.';
COMMENT ON COLUMN process_runs.kind IS
    'Run category. Closed set: crawl (internal fetch/collector runs). A new kind '
    'requires a CHECK update + a Go writer.';
