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
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import {
  TodoService,
  type TodoAdvanceAction,
  type TodoCreateRequest,
  type TodoRow,
} from '../../../../core/services/todo.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';
import type {
  PriorityLevel,
  TodoState,
} from '../../../../core/models/workbench.model';

type StateFilter = 'all' | TodoState;
type PriorityFilter = 'all' | PriorityLevel;

interface Chip<T extends string> {
  value: T;
  label: string;
}

const STATE_CHIPS: readonly Chip<StateFilter>[] = [
  { value: 'all', label: 'All' },
  { value: 'inbox', label: 'Inbox' },
  { value: 'todo', label: 'Todo' },
  { value: 'in_progress', label: 'In progress' },
  { value: 'done', label: 'Done' },
  { value: 'someday', label: 'Someday' },
];

const PRIORITY_CHIPS: readonly Chip<PriorityFilter>[] = [
  { value: 'all', label: 'All' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

const STATE_DOT_CLASS: Record<TodoState, string> = {
  inbox: 'bg-zinc-400',
  todo: 'bg-sky-400',
  in_progress: 'bg-amber-400',
  done: 'bg-emerald-500',
  someday: 'bg-zinc-600',
};

const STATE_TEXT_CLASS: Record<TodoState, string> = {
  inbox: 'text-zinc-300',
  todo: 'text-sky-300',
  in_progress: 'text-amber-300',
  done: 'text-emerald-300',
  someday: 'text-zinc-500',
};

const STATE_LABEL: Record<TodoState, string> = {
  inbox: 'inbox',
  todo: 'todo',
  in_progress: 'in progress',
  done: 'done',
  someday: 'someday',
};

const PRIORITY_LABEL: Record<PriorityLevel, string> = {
  high: 'high',
  medium: 'med',
  low: 'low',
};

const PRIORITY_TEXT_CLASS: Record<PriorityLevel, string> = {
  high: 'text-red-300',
  medium: 'text-amber-300',
  low: 'text-zinc-400',
};

/** State transitions per / */
const STATE_TRANSITIONS: Record<
  TodoState,
  readonly { action: TodoAdvanceAction; label: string }[]
> = {
  inbox: [
    { action: 'clarify', label: 'Clarify' },
    { action: 'drop', label: 'Drop' },
  ],
  todo: [
    { action: 'start', label: 'Start' },
    { action: 'defer', label: 'Defer' },
    { action: 'drop', label: 'Drop' },
  ],
  in_progress: [
    { action: 'complete', label: 'Complete' },
    { action: 'defer', label: 'Defer' },
  ],
  done: [],
  someday: [
    { action: 'clarify', label: 'Re-clarify' },
    { action: 'drop', label: 'Drop' },
  ],
};

/**
 * Todos list. Columns: State / Title / Priority / Due / Project /
 * Actions. Filter chips gate by state and priority. The capture input
 * at the top drops into the inbox; per-row buttons drive the
 * advance-state machine.
 *
 * Keyboard: j/k for row nav; Enter opens inline edit.
 */
@Component({
  selector: 'app-todos-list-page',
  standalone: true,
  imports: [DataTableComponent, DatePipe],
  templateUrl: './todos-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class TodosListPageComponent {
  private readonly todoService = inject(TodoService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly stateChips = STATE_CHIPS;
  protected readonly priorityChips = PRIORITY_CHIPS;

  protected readonly stateFilter = signal<StateFilter>('all');
  protected readonly priorityFilter = signal<PriorityFilter>('all');

  protected readonly resource = rxResource<
    TodoRow[],
    { state: StateFilter; priority: PriorityFilter }
  >({
    params: () => ({
      state: this.stateFilter(),
      priority: this.priorityFilter(),
    }),
    stream: ({ params }) =>
      this.todoService.list({
        state: params.state === 'all' ? undefined : params.state,
        priority: params.priority === 'all' ? undefined : params.priority,
        sort: 'priority',
      }),
  });

  protected readonly rows = computed(() => this.resource.value() ?? []);
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
  protected readonly endpointsUnavailable = computed(() => {
    if (this.resource.status() !== 'error') return false;
    const err = this.resource.error();
    if (err instanceof HttpErrorResponse) {
      return err.status === 404 || err.status === 405 || err.status === 501;
    }
    return false;
  });

  protected readonly focusedIndex = signal(0);
  private readonly rowRefs =
    viewChildren<ElementRef<HTMLTableRowElement>>('row');

  // Capture form — a single title input that posts to inbox. Keeps
  // the form minimal; richer capture happens via Cowork. Inbox is for
  // concrete work that needs later clarification.
  protected readonly captureDraft = signal('');
  private readonly _isActioning = signal(false);
  protected readonly isActioning = this._isActioning.asReadonly();

  constructor() {
    this.topbar.set({
      title: 'Todos',
      crumbs: ['Commitment', 'Todos'],
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

  protected setPriorityFilter(value: PriorityFilter): void {
    this.priorityFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected stateDotClass(state: TodoState): string {
    return STATE_DOT_CLASS[state];
  }

  protected stateTextClass(state: TodoState): string {
    return STATE_TEXT_CLASS[state];
  }

  protected stateLabel(state: TodoState): string {
    return STATE_LABEL[state];
  }

  protected priorityLabel(p: PriorityLevel | null): string {
    return p ? PRIORITY_LABEL[p] : '—';
  }

  protected priorityTextClass(p: PriorityLevel | null): string {
    return p ? PRIORITY_TEXT_CLASS[p] : 'text-zinc-500';
  }

  protected availableActions(
    state: TodoState,
  ): readonly { action: TodoAdvanceAction; label: string }[] {
    return STATE_TRANSITIONS[state];
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
  }

  protected readCaptureInput(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  protected submitCapture(): void {
    const title = this.captureDraft().trim();
    if (!title || this._isActioning()) return;

    const body: TodoCreateRequest = { title, state: 'inbox' };
    this._isActioning.set(true);
    this.todoService.create(body).subscribe({
      next: () => {
        this._isActioning.set(false);
        this.captureDraft.set('');
        this.notifications.success('Captured to inbox.');
        this.resource.reload();
      },
      error: (err: unknown) => {
        this._isActioning.set(false);
        const status = err instanceof HttpErrorResponse ? err.status : null;
        if (status === 404 || status === 405 || status === 501) {
          this.notifications.info(
            'Endpoint not yet available in backend (create todo).',
          );
        } else {
          this.notifications.error('Failed to capture.');
        }
      },
    });
  }

  protected advance(row: TodoRow, action: TodoAdvanceAction): void {
    if (this._isActioning()) return;
    this._isActioning.set(true);
    this.todoService.advance(row.id, action).subscribe({
      next: () => {
        this._isActioning.set(false);
        this.notifications.success(`${row.title} · ${action}.`);
        this.resource.reload();
      },
      error: (err: unknown) => {
        this._isActioning.set(false);
        const status = err instanceof HttpErrorResponse ? err.status : null;
        if (status === 400) {
          this.notifications.error('Illegal state transition.');
        } else if (status === 404 || status === 405 || status === 501) {
          this.notifications.info(
            'Endpoint not yet available in backend (advance todo).',
          );
        } else {
          this.notifications.error(`Failed to ${action}.`);
        }
      },
    });
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
