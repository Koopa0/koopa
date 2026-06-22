import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { DecimalPipe } from '@angular/common';
import { SystemService } from '../../../core/services/system.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../shared/components/data-table/data-table.component';
import { LoadingSpinnerComponent } from '../../../shared/components/loading-spinner/loading-spinner.component';
import { computeBreakdowns, computeProcessRunRows } from './stats-view';

/** One big-number cell on the inventory tile row. */
interface StatTile {
  id: string;
  label: string;
  value: number;
  /** Optional mono context line under the figure ("of 14", ...). */
  sub?: string;
}

/**
 * System stats page. Three independent reads — GET
 * /api/admin/system/stats (inventory tiles, breakdowns, process runs),
 * /stats/drift (area drift table), and /stats/learning (note growth +
 * weekly cadence). Each section degrades on its own: a failing read renders
 * an inline error with Retry while sibling sections stay live.
 */
@Component({
  selector: 'app-system-stats-page',
  imports: [DecimalPipe, DataTableComponent, LoadingSpinnerComponent],
  templateUrl: './system-stats.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class SystemStatsPageComponent {
  private readonly systemService = inject(SystemService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly overviewResource = rxResource({
    stream: () => this.systemService.getStats(),
  });
  private readonly driftResource = rxResource({
    stream: () => this.systemService.getDrift(),
  });
  private readonly learningResource = rxResource({
    stream: () => this.systemService.getLearningStats(),
  });

  // resource.value() throws while a resource is in the error state, so
  // every downstream read goes through these hasValue()-guarded views.
  protected readonly overview = computed(() =>
    this.overviewResource.hasValue()
      ? this.overviewResource.value()
      : undefined,
  );
  protected readonly drift = computed(() =>
    this.driftResource.hasValue() ? this.driftResource.value() : undefined,
  );
  protected readonly learning = computed(() =>
    this.learningResource.hasValue()
      ? this.learningResource.value()
      : undefined,
  );

  protected readonly overviewLoading = computed(
    () => this.overviewResource.status() === 'loading',
  );
  protected readonly overviewError = computed(
    () => this.overviewResource.status() === 'error',
  );
  protected readonly driftLoading = computed(
    () => this.driftResource.status() === 'loading',
  );
  protected readonly driftError = computed(
    () => this.driftResource.status() === 'error',
  );
  protected readonly learningLoading = computed(
    () => this.learningResource.status() === 'loading',
  );
  protected readonly learningError = computed(
    () => this.learningResource.status() === 'error',
  );

  protected readonly tiles = computed<StatTile[]>(() => {
    const v = this.overview();
    if (!v) return [];
    return [
      { id: 'contents', label: 'contents', value: v.contents.total },
      { id: 'published', label: 'published', value: v.contents.published },
      { id: 'collected', label: 'collected items', value: v.collected.total },
      {
        id: 'feeds',
        label: 'feeds enabled',
        value: v.feeds.enabled,
        sub: `of ${v.feeds.total}`,
      },
      { id: 'projects', label: 'projects', value: v.projects.total },
      { id: 'notes', label: 'notes', value: v.notes.total },
      {
        id: 'activity',
        label: 'events 24h',
        value: v.activity.last_24h,
        sub: `${v.activity.last_7d} in 7d`,
      },
    ];
  });

  protected readonly breakdowns = computed(() =>
    computeBreakdowns(this.overview()),
  );
  protected readonly processRunRows = computed(() =>
    computeProcessRunRows(this.overview()),
  );
  protected readonly driftAreas = computed(() => this.drift()?.areas ?? []);

  constructor() {
    this.topbar.set({
      title: 'Stats',
      crumbs: ['System', 'Stats'],
      actions: [
        {
          id: 'system-stats-refresh',
          label: 'Refresh',
          kind: 'secondary',
          run: () => this.reloadAll(),
        },
      ],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected retryOverview(): void {
    this.overviewResource.reload();
  }

  protected retryDrift(): void {
    this.driftResource.reload();
  }

  protected retryLearning(): void {
    this.learningResource.reload();
  }

  private reloadAll(): void {
    this.overviewResource.reload();
    this.driftResource.reload();
    this.learningResource.reload();
  }
}
