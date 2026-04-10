import {
  Component,
  ChangeDetectionStrategy,
  inject,
  computed,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  Rss,
  AlertTriangle,
  ExternalLink,
} from 'lucide-angular';
import { catchError, map, of, startWith } from 'rxjs';
import { FeedService } from '../../core/services/feed.service';
import { NotificationService } from '../../core/services/notification.service';
import { StatusBadgeComponent } from '../../shared/components/status-badge/status-badge.component';
import type { ApiFeed } from '../../core/models';

interface FeedState {
  feeds: ApiFeed[];
  isLoading: boolean;
}

@Component({
  selector: 'app-intelligence',
  standalone: true,
  imports: [DatePipe, LucideAngularModule, StatusBadgeComponent],
  templateUrl: './intelligence.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class IntelligenceComponent {
  private readonly feedService = inject(FeedService);
  private readonly notificationService = inject(NotificationService);

  private readonly state = toSignal(
    this.feedService.getFeeds().pipe(
      map(
        (response): FeedState => ({
          feeds: response.data ?? [],
          isLoading: false,
        }),
      ),
      catchError(() => {
        this.notificationService.error('Failed to load feed intelligence');
        return of<FeedState>({ feeds: [], isLoading: false });
      }),
      startWith<FeedState>({ feeds: [], isLoading: true }),
    ),
    { requireSync: true },
  );

  protected readonly feeds = computed(() => this.state().feeds);
  protected readonly isLoading = computed(() => this.state().isLoading);

  protected readonly enabledFeeds = computed(() =>
    this.feeds().filter((f) => f.enabled),
  );

  protected readonly failingFeeds = computed(() =>
    this.feeds().filter((f) => f.consecutive_failures > 0),
  );

  protected readonly totalFeeds = computed(() => this.feeds().length);
  protected readonly healthyCount = computed(
    () => this.enabledFeeds().length - this.failingFeeds().length,
  );

  // Icons
  protected readonly RssIcon = Rss;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly ExternalLinkIcon = ExternalLink;

  protected readonly SCHEDULE_LABELS: Record<string, string | undefined> = {
    hourly_4: 'Every 4 hours',
    daily: 'Daily',
    weekly: 'Weekly',
  };

  protected getScheduleLabel(schedule: string): string {
    return this.SCHEDULE_LABELS[schedule] ?? schedule;
  }
}
