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
import { Router, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { LearningService } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';
import type {
  PlanStatus,
  PlanSummary,
} from '../../../../core/models/learning.model';

const STATUS_DOT_CLASS: Record<PlanStatus, string> = {
  draft: 'bg-fg-subtle',
  active: 'bg-success',
  paused: 'bg-warn',
  completed: 'bg-info',
  abandoned: 'bg-error',
};

const STATUS_TEXT_CLASS: Record<PlanStatus, string> = {
  draft: 'text-fg-subtle',
  active: 'text-success',
  paused: 'text-warn',
  completed: 'text-info',
  abandoned: 'text-error',
};

/**
 * Plans List — Learning curricula. `GET /api/admin/learning/plans` returns
 * plan rows (draft + active only) with per-plan entry counts; rows open the
 * plan detail at `/admin/learning/plans/:id`. Columns: Title / Domain /
 * Status / Entries / Progress / Updated. The endpoint may return empty until
 * plans are created, so empty and error states are first-class.
 */
@Component({
  selector: 'app-plans-list-page',
  imports: [DataTableComponent, DatePipe, RouterLink],
  templateUrl: './plans-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class PlansListPageComponent {
  private readonly learningService = inject(LearningService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly resource = rxResource<PlanSummary[], void>({
    stream: () => this.learningService.plans(),
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

  protected readonly focusedIndex = signal(0);
  private readonly rowRefs =
    viewChildren<ElementRef<HTMLTableRowElement>>('row');

  constructor() {
    this.topbar.set({ title: 'Plans', crumbs: ['Learning', 'Plans'] });

    effect(() => {
      const idx = this.focusedIndex();
      const target = this.rowRefs()[idx];
      if (target && document.activeElement !== target.nativeElement) {
        target.nativeElement.focus({ preventScroll: false });
      }
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected openRow(row: PlanSummary): void {
    this.router.navigate(['/admin/learning/plans', row.id]);
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
  }

  protected statusDotClass(status: PlanStatus): string {
    return STATUS_DOT_CLASS[status];
  }

  protected statusTextClass(status: PlanStatus): string {
    return STATUS_TEXT_CLASS[status];
  }

  /** Completion as a 0–100 percentage; 0 when the plan has no entries. */
  protected progressPct(row: PlanSummary): number {
    return row.entry_total === 0
      ? 0
      : Math.round((row.entry_done / row.entry_total) * 100);
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
