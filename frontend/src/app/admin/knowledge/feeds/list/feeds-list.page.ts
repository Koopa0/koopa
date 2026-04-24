import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { DatePipe } from '@angular/common';
import { FeedService } from '../../../../core/services/feed.service';
import { NotificationService } from '../../../../core/services/notification.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import { DataTableComponent } from '../../../../shared/components/data-table/data-table.component';
import type { FeedRow } from '../../../../core/models/feed.model';

type HealthFilter = 'all' | 'healthy' | 'failing' | 'disabled';

const HEALTH_CHIPS: readonly HealthFilter[] = [
  'all',
  'healthy',
  'failing',
  'disabled',
];

/**
 * Feeds Health list-ish. Shows feed
 * health status, schedule, consecutive failures, last fetch time.
 *
 * Topbar [Open triage →] jumps to the card-based entry triage.
 * Row-level [Fetch now] posts to the force-fetch endpoint.
 */
@Component({
  selector: 'app-feeds-list-page',
  standalone: true,
  imports: [DataTableComponent, DatePipe],
  templateUrl: './feeds-list.page.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'flex min-h-full flex-1 flex-col' },
})
export class FeedsListPageComponent {
  private readonly feedService = inject(FeedService);
  private readonly notifications = inject(NotificationService);
  private readonly topbar = inject(AdminTopbarService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly healthChips = HEALTH_CHIPS;
  protected readonly healthFilter = signal<HealthFilter>('all');

  protected readonly resource = rxResource<FeedRow[], void>({
    stream: () => this.feedService.listFeeds(),
  });

  protected readonly allRows = computed(() => this.resource.value() ?? []);

  protected readonly rows = computed(() => {
    const filter = this.healthFilter();
    return this.allRows().filter((f) => {
      if (filter === 'all') return true;
      if (filter === 'disabled') return !f.enabled;
      if (filter === 'failing') return f.enabled && f.consecutive_failures > 0;
      return f.enabled && f.consecutive_failures === 0;
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

  private readonly _fetchingId = signal<string | null>(null);
  protected readonly fetchingId = this._fetchingId.asReadonly();

  constructor() {
    this.topbar.set({
      title: 'Feeds',
      crumbs: ['Knowledge', 'Feeds'],
      actions: [
        {
          id: 'open-triage',
          label: 'Open triage →',
          kind: 'primary',
          run: () => this.router.navigate(['/admin/knowledge/feeds/triage']),
        },
      ],
    });

    this.destroyRef.onDestroy(() => this.topbar.reset());
  }

  protected setHealthFilter(value: HealthFilter): void {
    this.healthFilter.set(value);
  }

  protected healthLabel(row: FeedRow): string {
    if (!row.enabled) return 'disabled';
    if (row.consecutive_failures > 0) return 'failing';
    return 'healthy';
  }

  protected healthTextClass(row: FeedRow): string {
    if (!row.enabled) return 'text-zinc-500';
    if (row.consecutive_failures > 0) return 'text-red-300';
    return 'text-emerald-300';
  }

  protected healthDotClass(row: FeedRow): string {
    if (!row.enabled) return 'bg-zinc-600';
    if (row.consecutive_failures > 0) return 'bg-red-500';
    return 'bg-emerald-500';
  }

  protected fetchNow(row: FeedRow): void {
    if (this._fetchingId()) return;
    this._fetchingId.set(row.id);
    this.feedService.fetchNow(row.id).subscribe({
      next: () => {
        this._fetchingId.set(null);
        this.notifications.success(`Fetch queued for ${row.name}.`);
      },
      error: () => {
        this._fetchingId.set(null);
        this.notifications.error('Failed to queue fetch.');
      },
    });
  }
}
