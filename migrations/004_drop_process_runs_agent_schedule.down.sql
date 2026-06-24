ALTER TABLE process_runs DROP CONSTRAINT process_runs_kind_check;
ALTER TABLE process_runs ADD CONSTRAINT process_runs_kind_check CHECK (kind IN ('crawl', 'agent_schedule'));
ALTER TABLE process_runs ADD COLUMN subsystem TEXT;
ALTER TABLE process_runs ADD CONSTRAINT chk_process_runs_subsystem_iff_agent_schedule
    CHECK ((kind = 'agent_schedule') = (subsystem IS NOT NULL));

COMMENT ON TABLE process_runs IS
    'Run-history records for background processes. kind discriminates: crawl '
    '(internal crawl/fetch runs such as RSS feed collector), agent_schedule '
    '(external AI scheduler runs). Kind-specific fields live in metadata. '
    'subsystem carries the external-AI-scheduler identifier (only when '
    'kind=agent_schedule). RETENTION: 90 days for terminal runs; pending/running '
    'rows are operational state.';
COMMENT ON COLUMN process_runs.kind IS
    'Run category. Closed set: crawl (internal fetch/collector runs), agent_schedule '
    '(external AI scheduler runs). New kinds require CHECK update + Go writer. '
    'Use this column for dashboards, retention scoping, and metric labels.';
COMMENT ON COLUMN process_runs.subsystem IS
    'External AI scheduler identifier. NOT NULL iff kind=''agent_schedule'' '
    '(chk_process_runs_subsystem_iff_agent_schedule).';
