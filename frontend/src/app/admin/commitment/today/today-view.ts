import type {
  CommittedItem,
  PendingDetail,
  RecurringTodo,
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
  kind: 'overdue' | 'today' | 'active' | 'upcoming';
  label: string;
  items: PendingDetail[];
}

/** Due-based day-progress figures for the strip, derived from section lengths. */
export interface ProgressFigures {
  open: number;
  completed: number;
  overdue: number;
  percent: number;
  doneWidth: number;
  overdueWidth: number;
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
 * Day-progress figures for the strip, derived from the section lengths the page
 * already renders: open = due-today + recurring-due + started work (the backend
 * dedups these against each other), overdue = the overdue section, completed =
 * what was finished today. Deriving from the same lists the optimistic mutators
 * patch keeps the strip live without a committed plan and without re-counting.
 */
export function computeFigures(v: TodayBrief | undefined): ProgressFigures {
  const open = v
    ? v.today_todos.length + v.recurring_todos.length + v.active_todos.length
    : 0;
  const overdue = v ? v.overdue_todos.length : 0;
  const completed = v ? v.completed_todos.length : 0;
  const total = open + overdue + completed;
  const ratio = (n: number): number =>
    total === 0 ? 0 : (n / total) * PERCENT;
  return {
    open,
    completed,
    overdue,
    percent: Math.round(ratio(completed)),
    doneWidth: ratio(completed),
    overdueWidth: ratio(overdue),
  };
}

/**
 * Overdue / due-today / in-progress / upcoming buckets, omitting the empty
 * ones. "In progress" carries the started-but-undated work the backend dedups
 * into active_todos — the bucket that was previously invisible on Today.
 */
export function buildLooseGroups(v: TodayBrief | undefined): LooseGroup[] {
  if (!v) return [];
  const groups: LooseGroup[] = [
    { kind: 'overdue', label: 'Overdue', items: v.overdue_todos },
    { kind: 'today', label: 'Due today', items: v.today_todos },
    { kind: 'active', label: 'In progress', items: v.active_todos },
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
    v.active_todos.length === 0 &&
    v.recurring_todos.length === 0 &&
    v.completed_todos.length === 0 &&
    v.upcoming_todos.length === 0 &&
    v.active_goals.length === 0 &&
    v.rss_highlights.length === 0
  );
}

const WEEKDAY_ABBR = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] as const;
const ALL_WEEKDAYS = 127;

/**
 * Short human label for a recurrence rule: "every N unit" for interval-mode,
 * "daily" for the full weekday mask, or the day abbreviations (Mon=bit0 ..
 * Sun=bit6, matching the backend ISODOW-1 mask).
 */
export function recurrenceSummary(item: RecurringTodo): string {
  if (item.recur_interval && item.recur_unit) {
    return `every ${item.recur_interval} ${item.recur_unit}`;
  }
  const mask = item.recur_weekdays ?? 0;
  if (mask === 0) return 'recurring';
  if (mask === ALL_WEEKDAYS) return 'daily';
  const days: string[] = [];
  for (let i = 0; i < WEEKDAY_ABBR.length; i++) {
    if (mask & (1 << i)) days.push(WEEKDAY_ABBR[i]);
  }
  return days.join(' ');
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

/**
 * Reflects a server-confirmed completion on the local brief: drops the todo
 * from every still-to-do section (the due buckets and today's recurring list)
 * and adds it to completed_todos, so the day-progress strip moves one unit from
 * open/overdue to completed without a refetch. Idempotent — a todo already in
 * completed_todos is not added twice (e.g. completing it from the plan list
 * after it was already dropped from a due bucket).
 */
export function markTodoCompleted(
  v: TodayBrief,
  todoId: string,
  title: string,
): TodayBrief {
  const alreadyCounted = v.completed_todos.some((t) => t.id === todoId);
  return {
    ...v,
    overdue_todos: v.overdue_todos.filter((t) => t.id !== todoId),
    today_todos: v.today_todos.filter((t) => t.id !== todoId),
    active_todos: v.active_todos.filter((t) => t.id !== todoId),
    upcoming_todos: v.upcoming_todos.filter((t) => t.id !== todoId),
    recurring_todos: v.recurring_todos.filter((t) => t.id !== todoId),
    completed_todos: alreadyCounted
      ? v.completed_todos
      : [{ id: todoId, title, state: 'done' as const }, ...v.completed_todos],
  };
}
