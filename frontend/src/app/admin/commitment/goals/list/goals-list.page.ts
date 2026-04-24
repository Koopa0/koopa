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
import { PlanService } from '../../../../core/services/plan.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';
import type {
  ActiveGoalSummary,
  GoalsOverview,
} from '../../../../core/models/admin.model';
import type { GoalStatus } from '../../../../core/models';

type StatusFilter = 'all' | 'active' | GoalStatus;

interface StatusChip {
  value: StatusFilter;
  label: string;
}

const STATUS_CHIPS: readonly StatusChip[] = [
  { value: 'active', label: 'Active' },
  { value: 'all', label: 'All' },
  { value: 'in_progress', label: 'In progress' },
  { value: 'not_started', label: 'Not started' },
  { value: 'on_hold', label: 'On hold' },
  { value: 'done', label: 'Done' },
  { value: 'abandoned', label: 'Abandoned' },
];

const STATUS_DOT_CLASS: Record<GoalStatus, string> = {
  not_started: 'bg-zinc-400',
  in_progress: 'bg-sky-400',
  on_hold: 'bg-amber-400',
  done: 'bg-emerald-500',
  abandoned: 'bg-zinc-600',
};

const STATUS_TEXT_CLASS: Record<GoalStatus, string> = {
  not_started: 'text-zinc-300',
  in_progress: 'text-sky-300',
  on_hold: 'text-amber-300',
  done: 'text-emerald-300',
  abandoned: 'text-zinc-500',
};

const STATUS_LABEL: Record<GoalStatus, string> = {
  not_started: 'not started',
  in_progress: 'in progress',
  on_hold: 'on hold',
  done: 'done',
  abandoned: 'abandoned',
};

/**
 * Goals List `/api/admin/commitment/goals` already
 * returns a cell-state envelope with all goals; filtering is
 * client-side so chip toggles don't refetch.
 *
 * Default chip is `active` (= `in_progress` OR `not_started`) since the
 * Today workflow cares about active commitments. The `all` chip keeps
 * archived / done rows reachable.
 */
@Component({
  selector: 'app-goals-list-page',
  standalone: true,
  imports: [DataTableComponent, DatePipe],
  templateUrl: './goals-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class GoalsListPageComponent {
  private readonly planService = inject(PlanService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly statusChips = STATUS_CHIPS;
  protected readonly statusFilter = signal<StatusFilter>('active');

  protected readonly resource = rxResource<GoalsOverview, void>({
    stream: () => this.planService.getGoalsOverview(),
  });

  protected readonly envelope = computed(() => this.resource.value());
  protected readonly allGoals = computed(() => this.envelope()?.goals ?? []);

  protected readonly rows = computed(() => {
    const filter = this.statusFilter();
    return this.allGoals().filter((g) => {
      if (filter === 'all') return true;
      if (filter === 'active')
        return g.status === 'in_progress' || g.status === 'not_started';
      return g.status === filter;
    });
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
      title: 'Goals & projects',
      crumbs: ['Commitment', 'Goals & projects'],
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

  protected setStatusFilter(value: StatusFilter): void {
    this.statusFilter.set(value);
    this.focusedIndex.set(0);
  }

  protected openRow(row: ActiveGoalSummary): void {
    this.router.navigate(['/admin/commitment/goals', row.id]);
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
  }

  protected statusDotClass(status: GoalStatus): string {
    return STATUS_DOT_CLASS[status];
  }

  protected statusTextClass(status: GoalStatus): string {
    return STATUS_TEXT_CLASS[status];
  }

  protected statusLabel(status: GoalStatus): string {
    return STATUS_LABEL[status];
  }

  protected milestonePercent(done: number, total: number): number {
    if (total === 0) return 0;
    return Math.round((done / total) * 100);
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
