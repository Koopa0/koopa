import { describe, expect, it } from 'vitest';
import type {
  DailyPlan,
  DailyPlanEntry,
} from '../../../core/services/daily-plan.service';
import {
  DAY_CLOSE_LOOKBACK_DAYS,
  appendTodoToToday,
  buildUnclosedDays,
  isUnresolved,
  lookbackDates,
  removeResolvedItem,
  totalUnresolved,
  type UnclosedDay,
} from './day-close-view';

/** Build a DailyPlanEntry with sane defaults; override per case. */
function entry(over: Partial<DailyPlanEntry> = {}): DailyPlanEntry {
  return {
    id: over.id ?? 'e-' + (over.todo_id ?? 't'),
    todo_id: over.todo_id ?? 't',
    title: over.title ?? 'A todo',
    state: over.state ?? 'planned',
    selected_by: over.selected_by ?? 'human',
    ...over,
  };
}

function plan(date: string, items: DailyPlanEntry[]): DailyPlan {
  return {
    date,
    items,
    total: items.length,
    done: items.filter((i) => i.state === 'done').length,
    overdue_count: 0,
  };
}

describe('isUnresolved', () => {
  // Bug: treating deferred/dropped/done as still-open would re-confront
  // items the user already decided on — defeating the whole "resolved
  // items drop out" model.
  const cases: { state: DailyPlanEntry['state']; want: boolean }[] = [
    { state: 'planned', want: true },
    { state: 'done', want: false },
    { state: 'deferred', want: false },
    { state: 'dropped', want: false },
  ];
  for (const c of cases) {
    it(`${c.state} → ${c.want}`, () => {
      expect(isUnresolved(entry({ state: c.state }))).toBe(c.want);
    });
  }
});

describe('lookbackDates', () => {
  it('returns lookbackDays past dates, newest first, excluding today', () => {
    // Bug: an off-by-one that includes today would offer to close a day
    // still in progress; one that starts at today-0 instead of today-1
    // would skip yesterday.
    const dates = lookbackDates(new Date(2026, 5, 17), 14);
    expect(dates).toHaveLength(14);
    expect(dates[0]).toBe('2026-06-16'); // yesterday, newest first
    expect(dates[13]).toBe('2026-06-03'); // 14 days back
    expect(dates).not.toContain('2026-06-17'); // today excluded
  });

  it('crosses a month boundary correctly', () => {
    // Bug: naive day subtraction on getDate() would underflow past the
    // 1st of the month instead of rolling into the prior month.
    const dates = lookbackDates(new Date(2026, 6, 2), 5); // 2026-07-02
    expect(dates).toEqual([
      '2026-07-01',
      '2026-06-30',
      '2026-06-29',
      '2026-06-28',
      '2026-06-27',
    ]);
  });

  it('uses the exported lookback constant for the production window', () => {
    expect(DAY_CLOSE_LOOKBACK_DAYS).toBe(14);
  });
});

describe('buildUnclosedDays', () => {
  it('keeps only days with unresolved items, drops fully-terminal days', () => {
    // Bug: surfacing a day whose every item is done/dropped would create
    // empty confrontation cards the user can do nothing about.
    const plans = [
      plan('2026-06-10', [entry({ todo_id: 'a', state: 'planned' })]),
      plan('2026-06-11', [entry({ todo_id: 'b', state: 'done' })]),
      plan('2026-06-12', []),
    ];
    const days = buildUnclosedDays(plans);
    expect(days.map((d) => d.date)).toEqual(['2026-06-10']);
  });

  it('strips terminal items but keeps the day for its unresolved ones', () => {
    // Bug: returning all items (not just unresolved) would ask the user
    // to re-decide a done item sitting next to an open one.
    const plans = [
      plan('2026-06-10', [
        entry({ todo_id: 'open', state: 'planned' }),
        entry({ todo_id: 'closed', state: 'done' }),
      ]),
    ];
    const [day] = buildUnclosedDays(plans);
    expect(day.unresolved.map((i) => i.todo_id)).toEqual(['open']);
    expect(day.plannedTotal).toBe(2); // header context keeps the full count
  });

  it('sorts confrontable days newest first regardless of input order', () => {
    // Bug: unsorted output would confront the oldest day first, burying
    // the most recent (and most actionable) unclosed day.
    const plans = [
      plan('2026-06-08', [entry({ todo_id: 'a' })]),
      plan('2026-06-12', [entry({ todo_id: 'b' })]),
      plan('2026-06-10', [entry({ todo_id: 'c' })]),
    ];
    expect(buildUnclosedDays(plans).map((d) => d.date)).toEqual([
      '2026-06-12',
      '2026-06-10',
      '2026-06-08',
    ]);
  });
});

describe('totalUnresolved', () => {
  it('sums unresolved items across days', () => {
    const days: UnclosedDay[] = [
      {
        date: '2026-06-10',
        unresolved: [entry({ todo_id: 'a' }), entry({ todo_id: 'b' })],
        plannedTotal: 2,
      },
      { date: '2026-06-09', unresolved: [entry({ todo_id: 'c' })], plannedTotal: 3 },
    ];
    expect(totalUnresolved(days)).toBe(3);
  });
});

describe('appendTodoToToday', () => {
  it('carries today planned rows in order and appends the re-planned todo', () => {
    // Bug: dropping the existing planned rows would wipe today's plan on
    // the atomic PUT (replace, not append on the server side).
    const today = [
      entry({ todo_id: 'x', state: 'planned' }),
      entry({ todo_id: 'y', state: 'planned' }),
    ];
    expect(appendTodoToToday(today, 'z')).toEqual([
      { todo_id: 'x', position: 0 },
      { todo_id: 'y', position: 1 },
      { todo_id: 'z', position: 2 },
    ]);
  });

  it('does not re-send terminal rows from today', () => {
    // Bug: re-sending a dropped/done todo_id from today's plan would
    // resurrect it as planned via the replace PUT.
    const today = [
      entry({ todo_id: 'live', state: 'planned' }),
      entry({ todo_id: 'gone', state: 'dropped' }),
      entry({ todo_id: 'fin', state: 'done' }),
    ];
    expect(appendTodoToToday(today, 'new')).toEqual([
      { todo_id: 'live', position: 0 },
      { todo_id: 'new', position: 1 },
    ]);
  });
});

describe('removeResolvedItem', () => {
  const base: UnclosedDay[] = [
    {
      date: '2026-06-10',
      unresolved: [entry({ todo_id: 'a' }), entry({ todo_id: 'b' })],
      plannedTotal: 2,
    },
    { date: '2026-06-09', unresolved: [entry({ todo_id: 'c' })], plannedTotal: 1 },
  ];

  it('pulls one item from its day, leaving siblings', () => {
    const next = removeResolvedItem(base, '2026-06-10', 'a');
    expect(next[0].unresolved.map((i) => i.todo_id)).toEqual(['b']);
  });

  it('drops a day whose last unresolved item is removed', () => {
    // Bug: leaving an empty day behind would render a card with no items
    // and no actions.
    const next = removeResolvedItem(base, '2026-06-09', 'c');
    expect(next.map((d) => d.date)).toEqual(['2026-06-10']);
  });

  it('leaves the model unchanged for an unknown date/todo', () => {
    expect(removeResolvedItem(base, '2026-06-10', 'missing')).toEqual(base);
  });
});
