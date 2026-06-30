import { HttpErrorResponse } from '@angular/common/http';
import type {
  DailyPlanEntry,
  DailyPlanWriteItem,
} from '../../../core/services/daily-plan.service';
import type {
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

// 'inbox' is not a Todos-page tab — it has its own page (InboxPageComponent),
// which reuses this view-model with view='inbox'. The Todos page tabs are the
// status-flow views in GTD_TABS. 'history' backs the Complete ("已了結") tab.
export type GtdView =
  | 'inbox'
  | 'pending'
  | 'in_progress'
  | 'someday'
  | 'history';

export interface GtdTab {
  view: GtdView;
  label: string;
}

/** The Todos-page tab strip — status-flow views only (Inbox is its own page). */
export const GTD_TABS: readonly GtdTab[] = [
  { view: 'pending', label: 'Pending' },
  { view: 'in_progress', label: 'In Progress' },
  { view: 'someday', label: 'Someday' },
  { view: 'history', label: 'Complete' },
];

/** Views where row selection and the triage keys are active. */
export function isTriageable(view: GtdView): boolean {
  return (
    view === 'inbox' ||
    view === 'pending' ||
    view === 'in_progress' ||
    view === 'someday'
  );
}

/** Coerce route data into a valid initial Todos view; default to pending. */
export function initialViewOf(value: unknown): GtdView {
  return GTD_TABS.some((t) => t.view === value) ? (value as GtdView) : 'pending';
}

export function viewLabel(view: GtdView): string {
  if (view === 'inbox') return 'Inbox';
  return GTD_TABS.find((t) => t.view === view)?.label ?? 'Pending';
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
  pending: {
    title: 'No clarified todos waiting',
    description: 'Clarify something from the inbox and it shows up here.',
  },
  in_progress: {
    title: 'Nothing in progress',
    description: 'Start a pending todo with e and it moves here.',
  },
  someday: {
    title: 'No someday/maybe',
    description:
      'Things you might do, but not now. Defer with d to park them here.',
  },
  history: {
    title: 'Nothing resolved yet',
    description: 'Done, dropped, and recurring completions are kept here.',
  },
};

export function emptyCopyFor(view: GtdView, searching: boolean): EmptyCopy {
  if (view === 'history' && searching) {
    return {
      title: 'No matches',
      description: 'No resolved todos match your search.',
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

/**
 * Today's calendar date (YYYY-MM-DD) in the owner's timezone (Asia/Taipei),
 * matching the backend day boundary (the Go handlers' today() and the MCP
 * server both roll the day at Asia/Taipei midnight). `new Date().toISOString()`
 * yields the UTC date, which trails Taipei by one day during 00:00–07:59 local,
 * dropping due-today todos from the GTD Today tab, miscounting tabs, and
 * mis-toning due chips. en-CA formats as YYYY-MM-DD.
 */
export function todayInTaipei(now: Date = new Date()): string {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Taipei',
  }).format(now);
}

/** Rows for the backlog-derived status views (inbox / pending / in_progress /
 *  someday). Recurring routines are excluded from the working tabs — they live
 *  in the routines overview, the Today dashboard's due-today list, and each
 *  row's detail panel — so the status flow stays free of daily routines. */
export function rowsForView(
  view: GtdView,
  rows: readonly TodoRow[],
  planTodoIds: ReadonlySet<string>,
): TodoRow[] {
  switch (view) {
    case 'inbox':
      return rows.filter((r) => r.state === 'inbox');
    case 'pending':
      // Clarified, not yet started, not already pulled into today's plan, and
      // not a recurring routine.
      return rows.filter(
        (r) =>
          r.state === 'todo' &&
          !planTodoIds.has(r.id) &&
          !isRecurringRow(r),
      );
    case 'in_progress':
      return rows.filter(
        (r) => r.state === 'in_progress' && !isRecurringRow(r),
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

/** Due chip with overdue/soon tone, compared on the civil (Asia/Taipei) day. */
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

const RECUR_WEEKDAY_ABBR = [
  'Mon',
  'Tue',
  'Wed',
  'Thu',
  'Fri',
  'Sat',
  'Sun',
] as const;
const RECUR_ALL_WEEKDAYS = 127;

/**
 * Recurrence badge for either mode: interval → "every 1d" / "every 2w" (unit
 * initial); weekday → "daily" for the full mask, else day abbreviations
 * ("Mon Thu"). Returns null for a non-recurring todo. Covers weekday-mode so a
 * weekday routine carries a badge in the backlog rows and the Recurring tab.
 */
export function recurLabel(
  interval?: number | null,
  unit?: string | null,
  weekdays?: number | null,
): string | null {
  if (interval && unit) return `every ${interval}${unit.charAt(0)}`;
  if (weekdays && weekdays > 0) {
    if (weekdays === RECUR_ALL_WEEKDAYS) return 'daily';
    const days: string[] = [];
    for (let i = 0; i < RECUR_WEEKDAY_ABBR.length; i++) {
      if (weekdays & (1 << i)) days.push(RECUR_WEEKDAY_ABBR[i]);
    }
    return days.join(' ');
  }
  return null;
}

/**
 * Whether a backlog row is recurring — true when EITHER mode is set. The
 * Pending tab uses this to exclude recurring todos (they live in the Recurring
 * tab); checking only recur_interval missed weekday-mode routines.
 */
export function isRecurringRow(r: {
  recur_interval?: number | null;
  recur_weekdays?: number | null;
}): boolean {
  return r.recur_interval != null || r.recur_weekdays != null;
}

export function energyOf(value?: string | null): EnergyLevel | null {
  return value === 'low' || value === 'medium' || value === 'high'
    ? value
    : null;
}

export interface ResolvedKind {
  label: string;
  symbol: string;
  tone: 'done' | 'dropped' | 'recurring';
}

/**
 * How a resolved (Complete-tab) row was closed, from its current state: a
 * terminal done, a dropped/filed todo (archived/dismissed), or a still-active
 * recurring routine whose occurrence was completed (it stays todo/in_progress).
 */
export function resolvedKindOf(state: TodoState | undefined): ResolvedKind {
  if (state === 'archived' || state === 'dismissed') {
    return { label: 'dropped', symbol: '✕', tone: 'dropped' };
  }
  if (state === 'todo' || state === 'in_progress') {
    return { label: 'recurring', symbol: '↻', tone: 'recurring' };
  }
  return { label: 'done', symbol: '✓', tone: 'done' };
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
    case 'in_progress':
      return [
        ...NAV_HINTS,
        { keys: 'e', label: 'complete' },
        { keys: 'd', label: 'defer' },
        { keys: 'r', label: 'recurrence' },
      ];
    case 'pending':
      return [
        ...NAV_HINTS,
        { keys: 'e', label: 'start' },
        { keys: 'd', label: 'defer' },
        { keys: 't', label: 'today' },
        { keys: 'r', label: 'recurrence' },
      ];
    case 'someday':
      return [
        ...NAV_HINTS,
        { keys: 'e', label: 'activate' },
        { keys: 't', label: 'today' },
        { keys: 'r', label: 'recurrence' },
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
  | 'pull'
  | 'recurrence';

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
    case 'r':
      // Recurrence applies to clarified rows (todo/in_progress/someday), not
      // inbox captures — those become recurring after clarify.
      return view !== 'inbox' ? 'recurrence' : null;
    default:
      return null;
  }
}

/** Live tab counts across the status views plus the resolved (Complete) count. */
export function viewCounts(
  backlog: readonly TodoRow[],
  planTodoIds: ReadonlySet<string>,
  historyCount: number,
): Record<GtdView, number> {
  const count = (view: GtdView): number =>
    rowsForView(view, backlog, planTodoIds).length;
  return {
    inbox: count('inbox'),
    pending: count('pending'),
    in_progress: count('in_progress'),
    someday: count('someday'),
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
