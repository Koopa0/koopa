import type { StatsOverview } from '../../../core/models/admin.model';

/** One key/count row inside a breakdown panel. */
export interface CountRow {
  key: string;
  count: number;
}

/** One titled key/count breakdown panel derived from the overview. */
export interface Breakdown {
  id: string;
  title: string;
  rows: CountRow[];
}

/** One process-run kind with its status counts flattened to columns. */
export interface ProcessRunRow {
  kind: string;
  total: number;
  completed: number;
  failed: number;
  running: number;
  pending: number;
}

/** Map → rows sorted by count descending, key ascending as tiebreak. */
export function sortedCounts(map: Record<string, number>): CountRow[] {
  return Object.entries(map)
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

/** The key/count breakdown panels rendered under the stat tiles. */
export function computeBreakdowns(v: StatsOverview | undefined): Breakdown[] {
  if (!v) return [];
  return [
    { id: 'contents-status', title: 'Contents by status', rows: sortedCounts(v.contents.by_status) },
    { id: 'contents-type', title: 'Contents by type', rows: sortedCounts(v.contents.by_type) },
    { id: 'collected-status', title: 'Collected by status', rows: sortedCounts(v.collected.by_status) },
    { id: 'activity-source', title: 'Activity by source', rows: sortedCounts(v.activity.by_source) },
  ];
}

/** Process-run kinds as table rows, alphabetical by kind. */
export function computeProcessRunRows(
  v: StatsOverview | undefined,
): ProcessRunRow[] {
  if (!v) return [];
  return Object.entries(v.process_runs)
    .map(([kind, s]) => ({
      kind,
      total: s.total,
      completed: s.by_status['completed'] ?? 0,
      failed: s.by_status['failed'] ?? 0,
      running: s.by_status['running'] ?? 0,
      pending: s.by_status['pending'] ?? 0,
    }))
    .sort((a, b) => a.kind.localeCompare(b.kind));
}
