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
import { PlanService } from '../../../../core/services/plan.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';
import type { ProjectSummary } from '../../../../core/models/admin.model';

type StatusFilter = 'all' | 'active' | string;

interface StatusChip {
  value: StatusFilter;
  label: string;
}

const STATUS_CHIPS: readonly StatusChip[] = [
  { value: 'active', label: 'Active' },
  { value: 'all', label: 'All' },
  { value: 'in_progress', label: 'In progress' },
  { value: 'planned', label: 'Planned' },
  { value: 'on_hold', label: 'On hold' },
  { value: 'done', label: 'Done' },
  { value: 'archived', label: 'Archived' },
];

// Project status is a free-form string on the server, so the dot/label
// lookups fall back to a neutral default for any unrecognised value.
const STATUS_DOT_CLASS: Record<string, string> = {
  planned: 'bg-fg-subtle',
  in_progress: 'bg-brand',
  on_hold: 'bg-warn',
  done: 'bg-success',
  archived: 'bg-fg-faint',
};

const STATUS_TEXT_CLASS: Record<string, string> = {
  planned: 'text-fg-muted',
  in_progress: 'text-brand',
  on_hold: 'text-warn',
  done: 'text-success',
  archived: 'text-fg-subtle',
};

const ACTIVE_STATUSES: ReadonlySet<string> = new Set([
  'in_progress',
  'planned',
]);

/**
 * Projects List — `GET /api/admin/commitment/projects` returns a
 * `{ projects: ProjectSummary[] }` envelope (the same shape the dashboard
 * reads through {@link PlanService.getProjectsOverview}). Filtering is
 * client-side so chip toggles don't refetch.
 *
 * Default chip is `active` (= `in_progress` OR `planned`) since the Today
 * workflow cares about live projects. The `all` chip keeps archived / done
 * rows reachable.
 */
@Component({
  selector: 'app-projects-list-page',
  imports: [DataTableComponent, DatePipe, RouterLink],
  templateUrl: './projects-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'flex min-h-full flex-1 flex-col',
    '(document:keydown)': 'handleKeydown($event)',
  },
})
export class ProjectsListPageComponent {
  private readonly planService = inject(PlanService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly statusChips = STATUS_CHIPS;
  protected readonly statusFilter = signal<StatusFilter>('active');

  protected readonly resource = rxResource<ProjectSummary[], void>({
    stream: () => this.planService.getProjectsOverview(),
  });

  // Guard the read: rxResource.value() throws while the resource is in an
  // error state, so gate on hasValue() (the repo idiom). hasError() drives
  // the banner separately.
  protected readonly allProjects = computed<ProjectSummary[]>(() =>
    this.resource.hasValue() ? this.resource.value() : [],
  );

  protected readonly rows = computed(() => {
    const filter = this.statusFilter();
    return this.allProjects().filter((p) => {
      if (filter === 'all') return true;
      if (filter === 'active') return ACTIVE_STATUSES.has(p.status);
      return p.status === filter;
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
      title: 'Projects',
      crumbs: ['Commitment', 'Projects'],
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

  protected openRow(row: ProjectSummary): void {
    this.router.navigate(['/admin/commitment/projects', row.id]);
  }

  protected rowTabIndex(i: number): number {
    return i === this.focusedIndex() ? 0 : -1;
  }

  protected statusDotClass(status: string): string {
    return STATUS_DOT_CLASS[status] ?? 'bg-fg-subtle';
  }

  protected statusTextClass(status: string): string {
    return STATUS_TEXT_CLASS[status] ?? 'text-fg-muted';
  }

  protected statusLabel(status: string): string {
    return status.replaceAll('_', ' ');
  }

  protected todoPercent(done: number, total: number): number {
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
