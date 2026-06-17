import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { DatePipe, DecimalPipe } from '@angular/common';
import { SystemService } from '../../../core/services/system.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import { StatusBadgeComponent } from '../../../shared/components/status-badge/status-badge.component';
import { LoadingSpinnerComponent } from '../../../shared/components/loading-spinner/loading-spinner.component';

/** One big-number cell inside a health panel. */
interface HealthTile {
  id: string;
  label: string;
  value: number;
  /** Semantic accent applied to the figure. */
  tone: 'default' | 'success' | 'error';
}

/**
 * System health page. One read — GET /api/admin/system/health — feeds
 * three panels: feed health (with the failing-feed list), pipeline
 * runs, and core database entity counts.
 */
@Component({
  selector: 'app-system-health-page',
  imports: [DatePipe, DecimalPipe, StatusBadgeComponent, LoadingSpinnerComponent],
  templateUrl: './system-health.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class SystemHealthPageComponent {
  private readonly systemService = inject(SystemService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly resource = rxResource({
    stream: () => this.systemService.getHealth(),
  });

  // resource.value() throws while the resource is in the error state,
  // so reads go through this hasValue()-guarded view.
  protected readonly health = computed(() =>
    this.resource.hasValue() ? this.resource.value() : undefined,
  );
  protected readonly isLoading = computed(
    () => this.resource.status() === 'loading',
  );
  protected readonly hasError = computed(
    () => this.resource.status() === 'error',
  );

  protected readonly feedTiles = computed<HealthTile[]>(() => {
    const h = this.health();
    if (!h) return [];
    return [
      { id: 'feeds-total', label: 'subscribed', value: h.feeds.total, tone: 'default' },
      { id: 'feeds-healthy', label: 'healthy', value: h.feeds.healthy, tone: 'success' },
      {
        id: 'feeds-failing',
        label: 'failing',
        value: h.feeds.failing,
        tone: h.feeds.failing > 0 ? 'error' : 'default',
      },
    ];
  });

  protected readonly pipelineTiles = computed<HealthTile[]>(() => {
    const h = this.health();
    if (!h) return [];
    return [
      {
        id: 'pipelines-runs',
        label: 'recent runs',
        value: h.pipelines.recent_runs,
        tone: 'default',
      },
      {
        id: 'pipelines-failed',
        label: 'failed',
        value: h.pipelines.failed,
        tone: h.pipelines.failed > 0 ? 'error' : 'success',
      },
    ];
  });

  protected readonly databaseTiles = computed<HealthTile[]>(() => {
    const h = this.health();
    if (!h) return [];
    const d = h.database;
    return [
      { id: 'db-contents', label: 'contents', value: d.contents_count, tone: 'default' },
      { id: 'db-todos', label: 'todos', value: d.todos_count, tone: 'default' },
      { id: 'db-notes', label: 'notes', value: d.notes_count, tone: 'default' },
      { id: 'db-attempts', label: 'attempts', value: d.attempts_count, tone: 'default' },
      { id: 'db-sessions', label: 'sessions', value: d.sessions_count, tone: 'default' },
      { id: 'db-concepts', label: 'concepts', value: d.concepts_count, tone: 'default' },
    ];
  });

  constructor() {
    this.topbar.set({
      title: 'Health',
      crumbs: ['System', 'Health'],
      actions: [
        {
          id: 'system-health-refresh',
          label: 'Refresh',
          kind: 'secondary',
          run: () => this.resource.reload(),
        },
      ],
    });
    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected retry(): void {
    this.resource.reload();
  }
}
