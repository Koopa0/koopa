import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { LucideAngularModule, Copy as CopyIcon } from 'lucide-angular';
import { TodoService } from '../../../../core/services/todo.service';
import { InspectorService } from '../../inspector.service';
import type {
  TodoDetail,
  TodoState,
} from '../../../../core/models/workbench.model';

interface DueDisplay {
  text: string;
  level: 'overdue' | 'today' | 'soon' | 'later' | 'done';
}

/** State → colored text mapping. */
const STATE_TEXT_CLASS: Record<TodoState, string> = {
  inbox: 'text-zinc-400',
  todo: 'text-sky-400',
  in_progress: 'text-amber-400',
  done: 'text-emerald-400',
  someday: 'text-zinc-500',
};

const STATE_LABEL: Record<TodoState, string> = {
  inbox: 'inbox',
  todo: 'todo',
  in_progress: 'in_progress',
  done: 'done',
  someday: 'someday',
};

/**
 * Todo Inspector — fact sheet for a single todo.
 *
 * Surfaces: state · project (clickable → Project Inspector) ·
 * `created_by` when it differs from `assignee` (a delegation signal) ·
 * recurring skip count when the todo is recurring · a copy-id button
 * for bouncing into Cowork.
 *
 * Read-only — mutations run through Cowork's `advance_work`.
 */
@Component({
  selector: 'app-todo-inspector',
  standalone: true,
  imports: [ClipboardModule, LucideAngularModule],
  templateUrl: './todo-inspector.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TodoInspectorComponent {
  readonly id = input.required<string>();

  private readonly todoService = inject(TodoService);
  protected readonly inspector = inject(InspectorService);

  protected readonly justCopied = signal(false);
  protected readonly CopyIcon = CopyIcon;

  protected readonly resource = rxResource<TodoDetail, string>({
    params: () => this.id(),
    stream: ({ params }) => this.todoService.get(params),
  });

  protected readonly todo = this.resource.value;
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  /** State as colored text class + label. */
  protected readonly stateText = computed(() => {
    const t = this.todo();
    if (!t) return null;
    return {
      class: STATE_TEXT_CLASS[t.state],
      label: STATE_LABEL[t.state],
    };
  });

  /** True when created_by differs from assignee — surface the row only then. */
  protected readonly createdByDifferent = computed(() => {
    const t = this.todo();
    return t ? t.created_by !== t.assignee : false;
  });

  /** Recurrence text including skip-count health signal when present. */
  protected readonly recurrenceText = computed(() => {
    const t = this.todo();
    if (!t?.recur_interval || !t.recur_unit) return null;
    let base = `every ${t.recur_interval} ${t.recur_unit}`;
    if (t.recur_interval === 1) {
      // singularize: "every 1 weeks" → "every week"
      base = `every ${t.recur_unit.replace(/s$/, '')}`;
    }
    const skipCount = t.recent_skip_count_30d ?? 0;
    if (skipCount > 0) {
      return {
        text: `Repeats ${base}`,
        skipNote: `· ${skipCount} skipped 30d`,
      };
    }
    return { text: `Repeats ${base}`, skipNote: null };
  });

  /** Relative due display — "overdue 2d", "today", "in 3 days", or completed text. */
  protected readonly due = computed<DueDisplay | null>(() => {
    const t = this.todo();
    if (!t) return null;
    if (t.state === 'done') {
      return { text: 'completed', level: 'done' };
    }
    if (!t.due) return null;
    const dueDate = new Date(t.due);
    const now = new Date();
    const dayMs = 24 * 60 * 60 * 1000;
    const startOfToday = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate(),
    ).getTime();
    const startOfDue = new Date(
      dueDate.getFullYear(),
      dueDate.getMonth(),
      dueDate.getDate(),
    ).getTime();
    const dayDiff = Math.round((startOfDue - startOfToday) / dayMs);
    if (dayDiff < 0) {
      const n = -dayDiff;
      return { text: `overdue ${n}d`, level: 'overdue' };
    }
    if (dayDiff === 0) {
      return { text: 'today', level: 'today' };
    }
    if (dayDiff <= 3) {
      return {
        text: `in ${dayDiff} day${dayDiff === 1 ? '' : 's'}`,
        level: 'soon',
      };
    }
    return {
      text: `in ${dayDiff} days`,
      level: 'later',
    };
  });

  protected onCopyTodoId(): void {
    this.justCopied.set(true);
    setTimeout(() => this.justCopied.set(false), 1500);
  }
}
