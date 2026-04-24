/** Process runs envelope: summary + stage aggregates + runs + total. */

export type ProcessRunStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'skipped';

export type ProcessRunKind = 'crawl' | 'agent_schedule';

export type StageCellState = 'ok' | 'warn' | 'error' | null;

/**
 * Stage summary row: `[label, value, state]`. A `null` state means the
 * row is informational and has no pass/warn/fail scoring.
 */
export type StageRow = readonly [
  label: string,
  value: number | string | null,
  state: StageCellState,
];

export interface ProcessRunStage {
  name: string;
  status: ProcessRunStatus;
  pct_ok: number;
  rows: StageRow[];
}

export interface ProcessRunSummaryCell {
  value: number;
  state: 'ok' | 'warn' | 'error';
}

export interface ProcessRunSummary {
  success_rate_24h: ProcessRunSummaryCell;
  avg_latency_seconds: number;
  in_retry: ProcessRunSummaryCell;
  failed_last_hour: ProcessRunSummaryCell;
}

export interface ProcessRun {
  id: string;
  when: string;
  kind: ProcessRunKind;
  subsystem: string | null;
  source: string | null;
  items: number | null;
  duration: string | null;
  status: ProcessRunStatus;
  error: string | null;
}

export interface ProcessRunsResponse {
  summary: ProcessRunSummary;
  stages: ProcessRunStage[];
  runs: ProcessRun[];
  total: number;
}
