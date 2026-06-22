import type {
  DailyPlanEntry,
  DailyPlanWriteItem,
} from '../../../core/services/daily-plan.service';
import type { TodoRow } from '../../../core/services/todo.service';

// Pure view logic for the daily-plan builder. The builder edits only the
// `planned` slice of the plan: the atomic PUT's DeletePlannedByDate clears
// just the planned rows, so done/deferred/dropped entries are historical
// and survive every write untouched. Keeping these functions pure makes the
// position-rewrite and candidate-filtering rules unit-testable without a
// component harness.

/** The editable slice of a plan — the entries a PUT replace can touch. */
export function plannedEntries(
  items: readonly DailyPlanEntry[],
): DailyPlanEntry[] {
  return items.filter((item) => item.state === 'planned');
}

/**
 * Build the full PUT body from the desired planned entries in array order,
 * rewriting positions 0..n-1. The server replaces only planned rows, so
 * sending exactly the planned set the user composed is the complete write.
 */
export function writeItemsFrom(
  planned: readonly DailyPlanEntry[],
): DailyPlanWriteItem[] {
  return planned.map((item, index) => ({
    todo_id: item.todo_id,
    position: index,
  }));
}

/** PUT body for the planned set plus one appended todo at the tail. */
export function appendWriteItems(
  planned: readonly DailyPlanEntry[],
  todoId: string,
): DailyPlanWriteItem[] {
  const write = writeItemsFrom(planned);
  write.push({ todo_id: todoId, position: write.length });
  return write;
}

/** PUT body for the planned set with one todo removed. */
export function removeWriteItems(
  planned: readonly DailyPlanEntry[],
  todoId: string,
): DailyPlanWriteItem[] {
  return writeItemsFrom(planned.filter((item) => item.todo_id !== todoId));
}

/**
 * Un-planned candidates for the add picker: state=todo rows not already in
 * the plan (any state — a done/dropped historical entry still occupies its
 * todo, so re-adding it would collide). inbox-state todos are excluded
 * because the PUT rejects them; clarify them first.
 */
export function unplannedCandidates(
  todos: readonly TodoRow[],
  planItems: readonly DailyPlanEntry[],
): TodoRow[] {
  const planned = new Set(planItems.map((item) => item.todo_id));
  return todos.filter(
    (todo) => todo.state === 'todo' && !planned.has(todo.id),
  );
}

/**
 * Whether removing `todoId` would empty the plan. The atomic PUT rejects an
 * empty items list (400), so the last planned item can't be removed through
 * the builder — it's dropped from Today instead.
 */
export function isLastPlanned(
  planned: readonly DailyPlanEntry[],
  todoId: string,
): boolean {
  return planned.length === 1 && planned[0].todo_id === todoId;
}
