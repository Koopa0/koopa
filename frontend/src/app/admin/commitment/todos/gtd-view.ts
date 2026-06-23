import { HttpErrorResponse } from '@angular/common/http';
import type {
  DailyPlanEntry,
  DailyPlanWriteItem,
} from '../../../core/services/daily-plan.service';
import type {
  RecurringBuckets,
  TodoItem,
  TodoRow,
  TodoUpdateRequest,
} from '../../../core/services/todo.service';
import type { EnergyLevel, TodoState } from '../../../core/models/workbench.model';

/**
 * Pure view-model helpers for the GTD page: view predicates over the
 * backlog rows, daily-plan membership math, chip/label formatting, and
 * the keyboard legend. Kept free of Angular so the page component
 * stays a thin binding layer.
 */

export type GtdView =
  | 'inbox'
  | 'today'
  | 'pending'
  | 'someday'
  | 'recurring'
  | 'history';

export interface GtdTab {
  view: GtdView;
  label: string;
}

export const GTD_TABS: readonly GtdTab[] = [
  { view: 'inbox', label: 'Inbox' },
  { view: 'today', label: 'Today' },
  { view: 'pending', label: 'Pending' },
  { view: 'someday', label: 'Someday' },
  { view: 'recurring', label: 'Recurring' },
  { view: 'history', label: 'History' },
];

/** Views where row selection and the triage keys are active. */
export function isTriageable(view: GtdView): boolean {
  return (
    view === 'inbox' ||
    view === 'today' ||
    view === 'pending' ||
    view === 'someday'
  );
}

/** Coerce route data into a valid initial view; default to inbox. */
export function initialViewOf(value: unknown): GtdView {
  return GTD_TABS.some((t) => t.view === value) ? (value as GtdView) : 'inbox';
}

export function viewLabel(view: GtdView): string {
  return GTD_TABS.find((t) => t.view === view)?.label ?? 'Inbox';
}

export interface EmptyCopy {
  title: string;
  description: string;
}

const EMPTY_COPY: Record<GtdView, EmptyCopy> = {
  inbox: {
    title: 'Inbox zero',
    description:
      'Nothing to clarify. Captures land here — clear them into todos, someday, or the bin.',
  },
  today: {
    title: 'Nothing pulled into today',
    description:
      'Pull pending todos in with t, or plan your day from the Plan view.',
  },
  pending: {
    title: 'No clarified todos waiting',
    description: 'Clarify something from the inbox and it shows up here.',
  },
  someday: {
    title: 'No someday/maybe',
    description:
      'Things you might do, but not now. Defer with d to park them here.',
  },
  recurring: {
    title: 'No recurring todos',
    description: 'Recurring routines surface here when they’re due.',
  },
  history: {
    title: 'No history yet',
    description: 'Completed todos are kept here.',
  },
};

export function emptyCopyFor(view: GtdView, searching: boolean): EmptyCopy {
  if (view === 'history' && searching) {
    return {
      title: 'No history yet',
      description: 'No completed todos match your search.',
    };
  }
  return EMPTY_COPY[view];
}

/** Plan membership for the Today view — everything not dropped. */
export function planMemberIds(
  items: readonly DailyPlanEntry[],
): Set<string> {
  const ids = new Set<string>();
  for (const item of items) {
    if (item.state !== 'dropped') ids.add(item.todo_id);
  }
  return ids;
}

/**
 * Build the full PUT body that appends one todo to today's plan.
 * Only `planned` entries are resent — done/deferred/dropped rows
 * survive the server's replace untouched.
 */
export function appendToPlan(
  items: readonly DailyPlanEntry[],
  todoId: string,
): DailyPlanWriteItem[] {
  const planned = items.filter((item) => item.state === 'planned');
  const write = planned.map((item, index) => ({
    todo_id: item.todo_id,
    position: index,
  }));
  write.push({ todo_id: todoId, position: planned.length });
  return write;
}

function dueDay(due: string | null | undefined): string | null {
  return due ? due.slice(0, 10) : null;
}

/** Rows for the four backlog-derived views. */
export function rowsForView(
  view: GtdView,
  rows: readonly TodoRow[],
  planTodoIds: ReadonlySet<string>,
  todayIso: string,
): TodoRow[] {
  switch (view) {
    case 'inbox':
      return rows.filter((r) => r.state === 'inbox');
    case 'today':
      // An in_progress todo is active work — it always belongs in Today
      // (with its Complete action) regardless of plan membership or due
      // date, so starting a task never makes it vanish from every view.
      return rows.filter(
        (r) =>
          r.state !== 'done' &&
          r.state !== 'inbox' &&
          (r.state === 'in_progress' ||
            planTodoIds.has(r.id) ||
            dueDay(r.due) === todayIso),
      );
    case 'pending':
      return rows.filter(
        (r) =>
          r.state === 'todo' &&
          !planTodoIds.has(r.id) &&
          r.recur_interval == null,
      );
    case 'someday':
      return rows.filter((r) => r.state === 'someday');
    default:
      return [];
  }
}

const MONTH_LABELS = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec',
] as const;

export interface DueChip {
  label: string;
  tone: 'overdue' | 'soon' | 'default';
}

/** Due chip with overdue/soon tone, compared on the UTC day. */
export function dueChip(
  due: string | null | undefined,
  todayIso: string,
): DueChip | null {
  const day = dueDay(due);
  if (!day) return null;
  if (day === todayIso) return { label: 'today', tone: 'soon' };
  const month = Number(day.slice(5, 7));
  const date = Number(day.slice(8, 10));
  const label = `${MONTH_LABELS[month - 1] ?? day} ${date}`;
  return { label, tone: day < todayIso ? 'overdue' : 'default' };
}

const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

/** Compact capture age: now / 5m / 3h / 2d. */
export function ageLabel(createdAt: string, now = Date.now()): string {
  const created = Date.parse(createdAt);
  if (Number.isNaN(created)) return '';
  const elapsed = Math.max(0, now - created);
  if (elapsed < MINUTE_MS) return 'now';
  if (elapsed < HOUR_MS) return `${Math.floor(elapsed / MINUTE_MS)}m`;
  if (elapsed < DAY_MS) return `${Math.floor(elapsed / HOUR_MS)}h`;
  return `${Math.floor(elapsed / DAY_MS)}d`;
}

/** Recurrence badge: "every 1d", "every 2w" (unit initial). */
export function recurLabel(
  interval?: number | null,
  unit?: string | null,
): string | null {
  if (!interval || !unit) return null;
  return `every ${interval}${unit.charAt(0)}`;
}

export function energyOf(value?: string | null): EnergyLevel | null {
  return value === 'low' || value === 'medium' || value === 'high'
    ? value
    : null;
}

/**
 * Which advance verb a non-inbox row takes next. `someday` rows go
 * through `activate` (someday → todo) so re-activation returns them to the
 * backlog rather than skipping straight to in_progress; `todo` rows start.
 */
export function advanceActionFor(
  state: TodoState,
): 'start' | 'activate' | 'complete' | null {
  if (state === 'todo') return 'start';
  if (state === 'someday') return 'activate';
  if (state === 'in_progress') return 'complete';
  return null;
}

export const ADVANCE_TOAST = {
  clarify: 'Clarified → todo',
  start: 'Started',
  complete: 'Completed',
  defer: 'Deferred → someday',
  activate: 'Activated → todo',
  drop: 'Dropped',
} as const;

/** Result of the clarify modal, ready for PUT + advance(clarify). */
export interface ClarifyResult {
  project_id: string | null;
  energy: EnergyLevel | null;
  due: string | null;
}

/** Field update for the clarify result; null when nothing was set. */
export function clarifyUpdate(result: ClarifyResult): TodoUpdateRequest | null {
  const body: TodoUpdateRequest = {};
  if (result.project_id) body.project_id = result.project_id;
  if (result.energy) body.energy = result.energy;
  if (result.due) body.due_date = result.due;
  return Object.keys(body).length > 0 ? body : null;
}

export interface KeyHint {
  keys: string;
  label: string;
}

const NAV_HINTS: readonly KeyHint[] = [{ keys: 'j / k', label: 'navigate' }];

/** Context-dependent footer key legend per view. */
export function keyboardLegend(view: GtdView): KeyHint[] {
  switch (view) {
    case 'inbox':
      return [
        ...NAV_HINTS,
        { keys: 'e', label: 'clarify' },
        { keys: 't', label: 'today' },
        { keys: 'd', label: 'defer' },
        { keys: 'x', label: 'drop' },
      ];
    case 'today':
      return [
        ...NAV_HINTS,
        { keys: 'e', label: 'advance' },
        { keys: 'd', label: 'defer' },
      ];
    case 'pending':
      return [
        ...NAV_HINTS,
        { keys: 'e', label: 'start' },
        { keys: 'd', label: 'defer' },
        { keys: 't', label: 'today' },
      ];
    case 'someday':
      return [
        ...NAV_HINTS,
        { keys: 'e', label: 'activate' },
        { keys: 't', label: 'today' },
      ];
    default:
      return [];
  }
}

/** True when the event target is an element that owns keystrokes. */
export function isInteractiveTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return (
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement ||
    target instanceof HTMLButtonElement ||
    target instanceof HTMLAnchorElement ||
    target.isContentEditable
  );
}

export type GtdKeyAction =
  | 'down'
  | 'up'
  | 'advance'
  | 'clarify'
  | 'defer'
  | 'drop'
  | 'pull';

/** Triage key → action for the active view; null = not bound here. */
export function keyActionFor(key: string, view: GtdView): GtdKeyAction | null {
  switch (key) {
    case 'j':
    case 'ArrowDown':
      return 'down';
    case 'k':
    case 'ArrowUp':
      return 'up';
    case 'e':
    case 'Enter':
      return 'advance';
    case 'c':
      return view === 'inbox' ? 'clarify' : null;
    case 'd':
      return view !== 'someday' ? 'defer' : null;
    case 'x':
      return view === 'inbox' ? 'drop' : null;
    case 't':
      return view === 'pending' || view === 'someday' || view === 'inbox'
        ? 'pull'
        : null;
    default:
      return null;
  }
}

export interface RecurringGroup {
  label: string;
  items: TodoItem[];
}

/** Non-empty recurring groups, due-today before overdue. */
export function recurringGroupsOf(
  buckets: RecurringBuckets | undefined,
): RecurringGroup[] {
  return [
    { label: 'Due today', items: buckets?.due_today ?? [] },
    { label: 'Overdue', items: buckets?.overdue ?? [] },
  ].filter((group) => group.items.length > 0);
}

/** Live tab counts across all six views. */
export function viewCounts(
  backlog: readonly TodoRow[],
  planTodoIds: ReadonlySet<string>,
  todayIso: string,
  buckets: RecurringBuckets | undefined,
  historyCount: number,
): Record<GtdView, number> {
  const count = (view: GtdView): number =>
    rowsForView(view, backlog, planTodoIds, todayIso).length;
  return {
    inbox: count('inbox'),
    today: count('today'),
    pending: count('pending'),
    someday: count('someday'),
    recurring:
      (buckets?.due_today.length ?? 0) + (buckets?.overdue.length ?? 0),
    history: historyCount,
  };
}

/** User-facing message for a failed GTD mutation. */
export function mutationErrorMessage(err: unknown): string {
  const status = err instanceof HttpErrorResponse ? err.status : null;
  return status === 400
    ? 'That state transition is not allowed.'
    : 'The change didn’t save — please try again.';
}
