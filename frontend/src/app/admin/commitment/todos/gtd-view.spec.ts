import type { DailyPlanEntry } from '../../../core/services/daily-plan.service';
import type { TodoRow } from '../../../core/services/todo.service';
import {
  ageLabel,
  appendToPlan,
  clarifyUpdate,
  dueChip,
  emptyCopyFor,
  initialViewOf,
  keyActionFor,
  planMemberIds,
  recurLabel,
  rowsForView,
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

  it('filters the four backlog views by the exact predicates', () => {
    expect(rowsForView('inbox', backlog, planIds, TODAY).map((r) => r.id)).toEqual(
      ['capture'],
    );
    expect(rowsForView('today', backlog, planIds, TODAY).map((r) => r.id)).toEqual(
      ['planned', 'due-today'],
    );
    expect(
      rowsForView('pending', backlog, planIds, TODAY).map((r) => r.id),
    ).toEqual(['due-today', 'pending']);
    expect(
      rowsForView('someday', backlog, planIds, TODAY).map((r) => r.id),
    ).toEqual(['parked']);
  });

  it('keeps a started (in_progress) todo in Today even when unplanned and not due today', () => {
    // Regression: starting a Pending todo (→ in_progress) once made it
    // vanish from every view when it was neither in the plan nor due today.
    const started = row({
      id: 'started',
      state: 'in_progress',
      due: '2026-06-20T00:00:00Z',
    });
    const ids = rowsForView('today', [started], new Set<string>(), TODAY).map(
      (r) => r.id,
    );
    expect(ids).toEqual(['started']);
  });

  it('counts every view, including recurring buckets and history length', () => {
    const counts = viewCounts(
      backlog,
      planIds,
      TODAY,
      {
        due_today: [],
        overdue: [],
      },
      7,
    );
    expect(counts).toEqual({
      inbox: 1,
      today: 2,
      pending: 2,
      someday: 1,
      recurring: 0,
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

  it('tones due chips by UTC day', () => {
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

  it('maps triage keys per view', () => {
    expect(keyActionFor('e', 'inbox')).toBe('advance');
    expect(keyActionFor('c', 'inbox')).toBe('clarify');
    expect(keyActionFor('c', 'pending')).toBeNull();
    expect(keyActionFor('x', 'inbox')).toBe('drop');
    expect(keyActionFor('x', 'today')).toBeNull();
    expect(keyActionFor('d', 'someday')).toBeNull();
    expect(keyActionFor('t', 'someday')).toBe('pull');
    expect(keyActionFor('t', 'inbox')).toBe('pull');
  });

  it('builds the clarify field update only from set fields', () => {
    expect(
      clarifyUpdate({ project_id: null, energy: null, due: null }),
    ).toBeNull();
    expect(
      clarifyUpdate({ project_id: 'p1', energy: 'high', due: '2026-06-12' }),
    ).toEqual({ project_id: 'p1', energy: 'high', due_date: '2026-06-12' });
  });

  it('falls back to inbox for unknown route data and swaps history empty copy while searching', () => {
    expect(initialViewOf('today')).toBe('today');
    expect(initialViewOf('nope')).toBe('inbox');
    expect(emptyCopyFor('history', true).description).toContain(
      'match your search',
    );
    expect(emptyCopyFor('history', false).description).toContain('kept here');
  });
});
