import type {
  DailyPlan,
  DailyPlanEntry,
  DailyPlanWriteItem,
} from '../../../core/services/daily-plan.service';

/**
 * Pure view-model helpers for the Day-close confrontation page: the
 * lookback date list, the "unresolved" predicate, grouping plans into
 * confrontable days, and the daily-plan write list for "re-plan to
 * today". Kept Angular-free so the page component stays a thin binding
 * layer and the logic is unit-testable without a TestBed.
 *
 * Design (no backend change, no "last close" marker): a day is
 * confrontable if it has at least one planned entry still in the
 * non-terminal `planned` state. Re-plan and drop mutate server state, so
 * a resolved item naturally falls out of the window on the next read;
 * only consciously-left items keep reappearing — that reappearance is
 * the no-auto-carryover confrontation feature, not a bug.
 */

/** How many days back the confrontation looks. */
export const DAY_CLOSE_LOOKBACK_DAYS = 14;

/**
 * A past day with at least one unresolved planned item, ready to
 * confront. `date` is the YYYY-MM-DD the plan belongs to; `items` are
 * only the unresolved entries (terminal-state rows are dropped — they
 * need no decision).
 */
export interface UnclosedDay {
  date: string;
  unresolved: DailyPlanEntry[];
  /** Total planned entries that day, resolved or not — context for the header. */
  plannedTotal: number;
}

/**
 * Lifecycle states that count as "done with" a planned entry — no
 * confrontation needed. `planned` is the only non-terminal state, so it
 * is the sole driver of the confrontation.
 */
const TERMINAL_STATES: ReadonlySet<DailyPlanEntry['state']> = new Set([
  'done',
  'deferred',
  'dropped',
]);

/** True when the entry still demands a decision (not in a terminal state). */
export function isUnresolved(entry: DailyPlanEntry): boolean {
  return !TERMINAL_STATES.has(entry.state);
}

/**
 * The ordered list of past YYYY-MM-DD dates to probe, newest first,
 * EXCLUDING `today` itself (today is not yet closeable). `lookbackDays`
 * dates are returned: yesterday back through `lookbackDays` days ago.
 *
 * `today` is taken as an explicit argument (not read from the clock) so
 * the function is deterministic and testable. It must be a local
 * calendar date; date math is done in UTC-noon to dodge DST edges.
 */
export function lookbackDates(today: Date, lookbackDays: number): string[] {
  const dates: string[] = [];
  // Anchor at UTC noon so adding whole days never lands on a DST gap.
  const anchor = Date.UTC(
    today.getFullYear(),
    today.getMonth(),
    today.getDate(),
    12,
  );
  const dayMs = 24 * 60 * 60 * 1000;
  for (let back = 1; back <= lookbackDays; back++) {
    dates.push(toIsoDate(new Date(anchor - back * dayMs)));
  }
  return dates;
}

/** Format a Date as a YYYY-MM-DD calendar date (UTC fields). */
function toIsoDate(date: Date): string {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  const day = String(date.getUTCDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/**
 * Reduce per-date plans into the confrontable set: keep only days that
 * carry at least one unresolved entry, newest first. Plans with no
 * planned items, or whose every entry is terminal, are dropped.
 *
 * Input plans may arrive in any order; output is sorted by date
 * descending so the most recent unclosed day leads.
 */
export function buildUnclosedDays(plans: readonly DailyPlan[]): UnclosedDay[] {
  const days: UnclosedDay[] = [];
  for (const plan of plans) {
    const unresolved = plan.items.filter(isUnresolved);
    if (unresolved.length === 0) {
      continue;
    }
    days.push({
      date: plan.date,
      unresolved,
      plannedTotal: plan.items.length,
    });
  }
  days.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
  return days;
}

/** Total unresolved items across all confrontable days. */
export function totalUnresolved(days: readonly UnclosedDay[]): number {
  return days.reduce((sum, day) => sum + day.unresolved.length, 0);
}

/**
 * Build the daily-plan PUT body that appends `todoId` to today's plan,
 * preserving the current planned entries in order. The PUT is an atomic
 * replace, so the full desired set must be sent: today's existing
 * planned rows plus the re-planned todo at the tail.
 *
 * `todayPlanned` is today's current plan entries (any state); only
 * `planned` rows are carried forward — terminal rows from today are not
 * re-sent (re-sending a dropped/done todo_id would resurrect it).
 */
export function appendTodoToToday(
  todayPlanned: readonly DailyPlanEntry[],
  todoId: string,
): DailyPlanWriteItem[] {
  const planned = todayPlanned.filter((entry) => entry.state === 'planned');
  const write: DailyPlanWriteItem[] = planned.map((entry, index) => ({
    todo_id: entry.todo_id,
    position: index,
  }));
  write.push({ todo_id: todoId, position: planned.length });
  return write;
}

/**
 * Remove a resolved entry (re-planned or dropped) from the confrontation
 * model in place of a refetch. Returns a NEW day list: the entry is
 * pulled from its day, and a day with no remaining unresolved entries is
 * dropped entirely.
 */
export function removeResolvedItem(
  days: readonly UnclosedDay[],
  date: string,
  todoId: string,
): UnclosedDay[] {
  const next: UnclosedDay[] = [];
  for (const day of days) {
    if (day.date !== date) {
      next.push(day);
      continue;
    }
    const unresolved = day.unresolved.filter(
      (entry) => entry.todo_id !== todoId,
    );
    if (unresolved.length === 0) {
      continue;
    }
    next.push({ ...day, unresolved });
  }
  return next;
}
