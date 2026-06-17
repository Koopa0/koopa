import { describe, expect, it } from 'vitest';

import type { DailyPlanEntry } from '../../../core/services/daily-plan.service';
import type { TodoRow } from '../../../core/services/todo.service';
import {
  appendWriteItems,
  isLastPlanned,
  plannedEntries,
  removeWriteItems,
  unplannedCandidates,
  writeItemsFrom,
} from './daily-plan-view';

function entry(
  todoId: string,
  state: DailyPlanEntry['state'] = 'planned',
): DailyPlanEntry {
  return {
    id: 'e-' + todoId,
    todo_id: todoId,
    title: todoId,
    state,
    selected_by: 'human',
  };
}

function todo(id: string, state: TodoRow['state'] = 'todo'): TodoRow {
  return {
    id,
    title: id,
    state,
    created_at: '2026-06-17T00:00:00Z',
    updated_at: '2026-06-17T00:00:00Z',
  };
}

describe('plannedEntries', () => {
  it('should keep only planned-state entries', () => {
    const items = [
      entry('a', 'planned'),
      entry('b', 'done'),
      entry('c', 'dropped'),
      entry('d', 'planned'),
    ];
    expect(plannedEntries(items).map((e) => e.todo_id)).toEqual(['a', 'd']);
  });
});

describe('writeItemsFrom', () => {
  it('should rewrite positions to array order', () => {
    const items = [entry('x'), entry('y'), entry('z')];
    expect(writeItemsFrom(items)).toEqual([
      { todo_id: 'x', position: 0 },
      { todo_id: 'y', position: 1 },
      { todo_id: 'z', position: 2 },
    ]);
  });
});

describe('appendWriteItems', () => {
  it('should append the new todo at the tail with the next position', () => {
    const planned = [entry('a'), entry('b')];
    expect(appendWriteItems(planned, 'c')).toEqual([
      { todo_id: 'a', position: 0 },
      { todo_id: 'b', position: 1 },
      { todo_id: 'c', position: 2 },
    ]);
  });
});

describe('removeWriteItems', () => {
  it('should drop the todo and re-number the rest', () => {
    const planned = [entry('a'), entry('b'), entry('c')];
    expect(removeWriteItems(planned, 'b')).toEqual([
      { todo_id: 'a', position: 0 },
      { todo_id: 'c', position: 1 },
    ]);
  });
});

describe('unplannedCandidates', () => {
  it('should exclude todos already in the plan and non-todo states', () => {
    const todos = [
      todo('a', 'todo'),
      todo('b', 'todo'),
      todo('c', 'inbox'),
      todo('d', 'todo'),
    ];
    // 'a' is already planned (any state counts — its todo is occupied).
    const planItems = [entry('a', 'planned'), entry('d', 'done')];
    expect(unplannedCandidates(todos, planItems).map((t) => t.id)).toEqual(['b']);
  });
});

describe('isLastPlanned', () => {
  it('should be true only when the todo is the sole planned entry', () => {
    expect(isLastPlanned([entry('only')], 'only')).toBe(true);
    expect(isLastPlanned([entry('a'), entry('b')], 'a')).toBe(false);
    expect(isLastPlanned([entry('a')], 'other')).toBe(false);
  });
});
