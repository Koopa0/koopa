import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  computed,
  effect,
  inject,
  signal,
  viewChildren,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { TaskService } from '../../../../core/services/task.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';
import type {
  CoordinationTask,
  TaskState,
} from '../../../../core/models/workbench.model';

type StateFilter = 'all' | TaskState;
type AssigneeFilter = 'all' | 'me';

interface StateChip {
  value: StateFilter;
  label: string;
}

// `canceled` is intentionally absent: listAll() unions /tasks/open
// + /tasks/completed, which do not surface canceled rows. Add the
// chip when the unified `GET /tasks?state=` endpoint ships.
const STATE_CHIPS: readonly StateChip[] = [
  { value: 'all', label: 'All' },
  { value: 'submitted', label: 'Submitted' },
  { value: 'working', label: 'Working' },
  { value: 'revision_requested', label: 'Revision' },
  { value: 'completed', label: 'Completed' },
];

const STATE_DOT_CLASS: Record<TaskState, string> = {
  submitted: 'bg-zinc-400',
  working: 'bg-sky-400',
  revision_requested: 'bg-amber-400',
  completed: 'bg-emerald-500',
  canceled: 'bg-zinc-600',
};

const STATE_TEXT_CLASS: Record<TaskState, string> = {
  submitted: 'text-zinc-300',
  working: 'text-sky-300',
  revision_requested: 'text-amber-300',
  completed: 'text-emerald-300',
  canceled: 'text-zinc-500',
};

const STATE_LABEL: Record<TaskState, string> = {
  submitted: 'submitted',
  working: 'working',
  revision_requested: 'revision',
  completed: 'completed',
  canceled: 'canceled',
};

/**
 * Tasks List. Backed by `TaskService.listAll()` which unions
 * `/tasks/open` + `/tasks/completed` client-side until the backend
 * consolidates onto a single `/tasks?state=` endpoint.
 *
 * Columns: Title / Source / Assignee / State / Updated / ID.
 * Keyboard: host `(document:keydown)` for `j/k`; Enter is owned by
 * each row via `(keydown.enter)`.
 */
@Component({
  selector: 'app-tasks-list-page',
  standalone: true,
  imports: [DataTableComponent, DatePipe],
  templateUrl: './tasks-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class TasksListPageComponent {
  private readonly taskService = inject(TaskService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly stateChips = STATE_CHIPS;

  protected readonly stateFilter = signal<StateFilter>('all');
  protected readonly assigneeFilter = signal<AssigneeFilter>('all');

  protected readonly resource = rxResource<CoordinationTask[], void>({
    stream: () => this.taskService.listAll(),
  });

  protected readonly allRows = computed(() => this.resource.value() ?? []);

  protected readonly rows = computed(() => {
    const state = this.stateFilter();
    const assignee = this.assigneeFilter();
    return this.allRows()
      .filter((t) => state === 'all' || t.state === state)
      .filter((t) => assignee === 'all' || t.target === 'human')
      .sort(
        (a, b) =>
          new Date(b.submitted_at).getTime() -
          new Date(a.submitted_at).getTime(),
      );
  });

  protected readonly total = computed(() => this.rows().length);
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly isEmpty = computed(
    () => !this.isLoading() && this.rows().length === 0,
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  protected readonly focusedIndex = signal(0);

  private readonly rowRefs =
    viewChildren<ElementRef<HTMLTableRowElement>>('row');

  constructor() {
    this.topbar.set({
      title: 'Tasks',
      crumbs: ['Coordination', 'Tasks'],
    });

    effect(() => {
      const idx = this.focusedIndex();
      const target = this.rowRefs()[idx];
      if (target && document.activeElement !== target.nativeElement) {
        target.nativeElement.focus({ preventScroll: false });
      }
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setStateFilter(value: StateFilter): void {
    this.stateFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected setAssigneeFilter(value: AssigneeFilter): void {
    this.assigneeFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected openRow(row: CoordinationTask): void {
    this.router.navigate(['/admin/coordination/tasks', row.id]);
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
  }

  protected stateDotClass(state: TaskState): string {
    return STATE_DOT_CLASS[state];
  }

  protected stateTextClass(state: TaskState): string {
    return STATE_TEXT_CLASS[state];
  }

  protected stateLabel(state: TaskState): string {
    return STATE_LABEL[state];
  }

  protected handleKeydown(event: KeyboardEvent): void {
    if (isFormControl(event.target)) return;
    if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey)
      return;

    const rows = this.rows();
    if (rows.length === 0) return;

    if (event.key === 'j') {
      event.preventDefault();
      this.focusedIndex.update((i) => Math.min(i + 1, rows.length - 1));
    } else if (event.key === 'k') {
      event.preventDefault();
      this.focusedIndex.update((i) => Math.max(i - 1, 0));
    }
  }
}

function isFormControl(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return (
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement ||
    target.isContentEditable
  );
}
