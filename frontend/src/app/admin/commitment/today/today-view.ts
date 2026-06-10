import type {
  CommittedItem,
  PendingDetail,
  TodayBrief,
} from './today.service';
import type { BadgeVariant } from '../../../shared/components/status-badge/status-badge.component';
import type { GoalStatus } from '../../../core/models/api.model';
import type { EnergyLevel } from '../../../core/models/workbench.model';

/**
 * Pure view-model helpers for the Today page: day-progress figures,
 * loose-todo grouping, advance-state transforms on the local brief
 * copy, and small display mappings. Kept free of Angular so the page
 * component stays a thin binding layer.
 */

/** A labelled group of loose (unplanned) todos for the combined panel. */
export interface LooseGroup {
  kind: 'overdue' | 'today' | 'upcoming';
  label: string;
  items: PendingDetail[];
}

/** Live day-progress figures derived from the committed plan rows. */
export interface PlanFigures {
  planned: number;
  completed: number;
  deferred: number;
  percent: number;
  doneWidth: number;
  deferredWidth: number;
}

export const GOAL_VARIANT: Record<GoalStatus, BadgeVariant> = {
  not_started: 'neutral',
  in_progress: 'info',
  on_hold: 'warning',
  done: 'success',
  abandoned: 'neutral',
};

const TITLE_TRUNCATE_LENGTH = 30;
const MORNING_END_HOUR = 12;
const AFTERNOON_END_HOUR = 18;
const NIGHT_END_HOUR = 5;
const PERCENT = 100;

export function truncateTitle(title: string): string {
  return title.length <= TITLE_TRUNCATE_LENGTH
    ? title
    : `${title.slice(0, TITLE_TRUNCATE_LENGTH)}…`;
}

export function greetingForHour(hour: number): string {
  if (hour < NIGHT_END_HOUR) return 'Good evening';
  if (hour < MORNING_END_HOUR) return 'Good morning';
  if (hour < AFTERNOON_END_HOUR) return 'Good afternoon';
  return 'Good evening';
}

export function energyOf(value?: string | null): EnergyLevel | null {
  return value === 'low' || value === 'medium' || value === 'high'
    ? value
    : null;
}

/** Which advance verb a committed row needs next; null when terminal. */
export function planAdvanceAction(
  item: CommittedItem,
): 'start' | 'complete' | null {
  if (item.todo_state === 'todo') return 'start';
  if (item.todo_state === 'in_progress') return 'complete';
  return null;
}

/**
 * Day-progress figures, counted live from the committed rows so the
 * strip and the plan stay on one source. plan_completion is only the
 * fallback when the plan section degraded to an empty list. Dropped
 * rows count toward no bucket, matching the backend aggregation.
 */
export function computeFigures(v: TodayBrief | undefined): PlanFigures {
  let planned = 0;
  let completed = 0;
  let deferred = 0;
  if (v && v.committed_todos.length > 0) {
    for (const item of v.committed_todos) {
      if (item.status === 'planned') planned++;
      else if (item.status === 'done') completed++;
      else if (item.status === 'deferred') deferred++;
    }
  } else if (v) {
    ({ planned, completed, deferred } = v.plan_completion);
  }
  const total = planned + completed + deferred;
  const ratio = (n: number): number =>
    total === 0 ? 0 : (n / total) * PERCENT;
  return {
    planned,
    completed,
    deferred,
    percent: Math.round(ratio(completed)),
    doneWidth: ratio(completed),
    deferredWidth: ratio(deferred),
  };
}

/** Overdue / today / upcoming buckets, omitting the empty ones. */
export function buildLooseGroups(v: TodayBrief | undefined): LooseGroup[] {
  if (!v) return [];
  const groups: LooseGroup[] = [
    { kind: 'overdue', label: 'Overdue', items: v.overdue_todos },
    { kind: 'today', label: 'Due today', items: v.today_todos },
    { kind: 'upcoming', label: 'Upcoming', items: v.upcoming_todos },
  ];
  return groups.filter((g) => g.items.length > 0);
}

/** True when every section is empty — drives the teaching empty state. */
export function isQuietBrief(v: TodayBrief): boolean {
  return (
    v.committed_todos.length === 0 &&
    v.overdue_todos.length === 0 &&
    v.today_todos.length === 0 &&
    v.upcoming_todos.length === 0 &&
    v.active_goals.length === 0 &&
    v.unverified_hypotheses.length === 0 &&
    v.rss_highlights.length === 0 &&
    !v.active_session
  );
}

/** Reflects a server-confirmed advance on the committed plan row. */
export function applyPlanAdvance(
  v: TodayBrief,
  itemId: string,
  action: 'start' | 'complete',
): TodayBrief {
  return {
    ...v,
    committed_todos: v.committed_todos.map((item) =>
      item.id === itemId
        ? {
            ...item,
            todo_state: action === 'complete' ? 'done' : 'in_progress',
            status: action === 'complete' ? ('done' as const) : item.status,
          }
        : item,
    ),
  };
}

/** Drops a completed loose todo from every due bucket. */
export function removeLooseTodo(v: TodayBrief, todoId: string): TodayBrief {
  return {
    ...v,
    overdue_todos: v.overdue_todos.filter((t) => t.id !== todoId),
    today_todos: v.today_todos.filter((t) => t.id !== todoId),
    upcoming_todos: v.upcoming_todos.filter((t) => t.id !== todoId),
  };
}
