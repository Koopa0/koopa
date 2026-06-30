import type { DailyPlanEntry } from '../../../core/services/daily-plan.service';
import type { TodoRow } from '../../../core/services/todo.service';
import {
  ageLabel,
  appendToPlan,
  clarifyUpdate,
  dueChip,
  emptyCopyFor,
  initialViewOf,
  isRecurringRow,
  keyActionFor,
  planMemberIds,
  recurLabel,
  resolvedKindOf,
  rowsForView,
  todayInTaipei,
  viewCounts,
} from './gtd-view';

const TODAY = '2026-06-10';

function row(partial: Partial<TodoRow> & { id: string }): TodoRow {
  return {
    title: partial.id,
    state: 'todo',
    created_at: '2026-06-01T00:00:00Z',
    updated_at: '2026-06-01T00:00:00Z',
    ...partial,
  };
}

function planEntry(
  partial: Partial<DailyPlanEntry> & { todo_id: string },
): DailyPlanEntry {
  return {
    id: `plan-${partial.todo_id}`,
    title: partial.todo_id,
    state: 'planned',
    selected_by: 'human',
    ...partial,
  };
}

describe('gtd-view', () => {
  const backlog: TodoRow[] = [
    row({ id: 'capture', state: 'inbox' }),
    row({ id: 'planned', state: 'in_progress' }),
    row({ id: 'due-today', state: 'todo', due: `${TODAY}T00:00:00Z` }),
    row({ id: 'pending', state: 'todo', due: '2026-06-20T00:00:00Z' }),
    row({
      id: 'routine',
      state: 'todo',
      recur_interval: 1,
      recur_unit: 'days',
    }),
    row({ id: 'parked', state: 'someday' }),
    row({ id: 'shipped', state: 'done' }),
  ];
  const planIds = new Set(['planned']);

  it('filters the status views by the exact predicates', () => {
    expect(rowsForView('inbox', backlog, planIds).map((r) => r.id)).toEqual([
      'capture',
    ]);
    expect(
      rowsForView('pending', backlog, planIds).map((r) => r.id),
    ).toEqual(['due-today', 'pending']);
    // In Progress = state in_progress, recurring excluded. 'planned' is the
    // in_progress row in the backlog; its plan membership does not hide it.
    expect(
      rowsForView('in_progress', backlog, planIds).map((r) => r.id),
    ).toEqual(['planned']);
    expect(rowsForView('someday', backlog, planIds).map((r) => r.id)).toEqual([
      'parked',
    ]);
  });

  it('excludes recurring routines from the In Progress tab', () => {
    const rows: TodoRow[] = [
      row({ id: 'started', state: 'in_progress' }),
      row({
        id: 'started-routine',
        state: 'in_progress',
        recur_weekdays: 127,
      }),
    ];
    expect(
      rowsForView('in_progress', rows, new Set<string>()).map((r) => r.id),
    ).toEqual(['started']);
  });

  it('counts every status view plus the resolved (Complete) length', () => {
    const counts = viewCounts(backlog, planIds, 7);
    expect(counts).toEqual({
      inbox: 1,
      pending: 2,
      in_progress: 1,
      someday: 1,
      history: 7,
    });
  });

  it('treats dropped plan entries as non-members', () => {
    const ids = planMemberIds([
      planEntry({ todo_id: 'a' }),
      planEntry({ todo_id: 'b', state: 'dropped' }),
      planEntry({ todo_id: 'c', state: 'done' }),
    ]);
    expect([...ids].sort()).toEqual(['a', 'c']);
  });

  it('appends to the plan by resending only planned entries in order', () => {
    const items = [
      planEntry({ todo_id: 'a' }),
      planEntry({ todo_id: 'done', state: 'done' }),
      planEntry({ todo_id: 'b' }),
    ];
    expect(appendToPlan(items, 'new')).toEqual([
      { todo_id: 'a', position: 0 },
      { todo_id: 'b', position: 1 },
      { todo_id: 'new', position: 2 },
    ]);
  });

  it('tones due chips by civil (Asia/Taipei) day', () => {
    expect(dueChip(`${TODAY}T08:00:00Z`, TODAY)).toEqual({
      label: 'today',
      tone: 'soon',
    });
    expect(dueChip('2026-06-05T00:00:00Z', TODAY)).toEqual({
      label: 'Jun 5',
      tone: 'overdue',
    });
    expect(dueChip('2026-07-01T00:00:00Z', TODAY)).toEqual({
      label: 'Jul 1',
      tone: 'default',
    });
    expect(dueChip(null, TODAY)).toBeNull();
  });

  it('formats capture age compactly', () => {
    const now = Date.parse('2026-06-10T12:00:00Z');
    expect(ageLabel('2026-06-10T11:59:40Z', now)).toBe('now');
    expect(ageLabel('2026-06-10T11:30:00Z', now)).toBe('30m');
    expect(ageLabel('2026-06-10T03:00:00Z', now)).toBe('9h');
    expect(ageLabel('2026-06-01T12:00:00Z', now)).toBe('9d');
  });

  it('formats the recurrence badge from interval + unit initial', () => {
    expect(recurLabel(1, 'days')).toBe('every 1d');
    expect(recurLabel(2, 'weeks')).toBe('every 2w');
    expect(recurLabel(null, null)).toBeNull();
  });

  it('formats the recurrence badge for weekday-mode (daily / day list)', () => {
    expect(recurLabel(null, null, 127)).toBe('daily');
    // Mon (bit0=1) + Thu (bit3=8) = 9, in week order.
    expect(recurLabel(null, null, 9)).toBe('Mon Thu');
    expect(recurLabel(null, null, 0)).toBeNull();
    expect(recurLabel(null, null, null)).toBeNull();
    // Interval mode wins when both are somehow present.
    expect(recurLabel(3, 'days', 127)).toBe('every 3d');
  });

  it('treats either recurrence mode as recurring (isRecurringRow)', () => {
    expect(isRecurringRow({ recur_interval: 2, recur_weekdays: null })).toBe(
      true,
    );
    expect(isRecurringRow({ recur_interval: null, recur_weekdays: 127 })).toBe(
      true,
    );
    expect(isRecurringRow({ recur_interval: null, recur_weekdays: null })).toBe(
      false,
    );
  });

  it('excludes weekday-mode recurring todos from the Pending tab', () => {
    const rows: TodoRow[] = [
      row({ id: 'plain', state: 'todo' }),
      row({ id: 'interval-recur', state: 'todo', recur_interval: 2, recur_unit: 'days' }),
      row({ id: 'weekday-recur', state: 'todo', recur_weekdays: 127 }),
    ];
    // Only the non-recurring todo remains; BOTH recurrence modes are excluded
    // (weekday-mode was the leak this fix closes).
    expect(
      rowsForView('pending', rows, new Set<string>()).map((r) => r.id),
    ).toEqual(['plain']);
  });

  it('maps triage keys per view', () => {
    expect(keyActionFor('e', 'inbox')).toBe('advance');
    expect(keyActionFor('c', 'inbox')).toBe('clarify');
    expect(keyActionFor('c', 'pending')).toBeNull();
    expect(keyActionFor('x', 'inbox')).toBe('drop');
    expect(keyActionFor('x', 'pending')).toBeNull();
    expect(keyActionFor('d', 'someday')).toBeNull();
    expect(keyActionFor('t', 'someday')).toBe('pull');
    expect(keyActionFor('t', 'inbox')).toBe('pull');
  });

  it('returns the Asia/Taipei civil date, not the UTC date, at the boundary', () => {
    // 17:00 UTC on Jun 9 is 01:00 Taipei on Jun 10. A UTC-based impl would
    // return '2026-06-09'; the Taipei civil date is '2026-06-10'. Injecting a
    // fixed instant makes this deterministic (no wall-clock dependence) and the
    // expected value is hand-computed, so it catches both a UTC-revert and a
    // wrong-timezone — not a tautology.
    expect(todayInTaipei(new Date('2026-06-09T17:00:00Z'))).toBe('2026-06-10');
    // Mid-afternoon Taipei (same civil day in both zones) — format sanity.
    expect(todayInTaipei(new Date('2026-06-10T06:00:00Z'))).toBe('2026-06-10');
  });

  it('maps a resolved row to its kind by state', () => {
    expect(resolvedKindOf('done')).toEqual({
      label: 'done',
      symbol: '✓',
      tone: 'done',
    });
    expect(resolvedKindOf('dismissed').tone).toBe('dropped');
    expect(resolvedKindOf('archived').tone).toBe('dropped');
    // A still-active recurring routine (todo/in_progress) reads as recurring.
    expect(resolvedKindOf('in_progress').tone).toBe('recurring');
    expect(resolvedKindOf('todo').tone).toBe('recurring');
  });

  it('builds the clarify field update only from set fields', () => {
    expect(
      clarifyUpdate({ project_id: null, energy: null, due: null }),
    ).toBeNull();
    expect(
      clarifyUpdate({ project_id: 'p1', energy: 'high', due: '2026-06-12' }),
    ).toEqual({ project_id: 'p1', energy: 'high', due_date: '2026-06-12' });
  });

  it('falls back to pending for unknown route data and swaps Complete empty copy while searching', () => {
    expect(initialViewOf('someday')).toBe('someday');
    expect(initialViewOf('today')).toBe('pending');
    expect(initialViewOf('nope')).toBe('pending');
    expect(emptyCopyFor('history', true).description).toContain(
      'match your search',
    );
    expect(emptyCopyFor('history', false).description).toContain(
      'recurring completions',
    );
  });
});
