import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { DatePipe } from '@angular/common';
import {
  LucideAngularModule,
  Rss,
  AlertTriangle,
  ExternalLink,
} from 'lucide-angular';
import { FeedService } from '../../core/services/feed.service';
import { NotificationService } from '../../core/services/notification.service';
import { StatusBadgeComponent } from '../../shared/components/status-badge/status-badge.component';
import type { ApiFeed } from '../../core/models';

@Component({
  selector: 'app-intelligence',
  standalone: true,
  imports: [DatePipe, LucideAngularModule, StatusBadgeComponent],
  templateUrl: './intelligence.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class IntelligenceComponent implements OnInit {
  private readonly feedService = inject(FeedService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly feeds = signal<ApiFeed[]>([]);
  protected readonly isLoading = signal(true);

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

  ngOnInit(): void {
    this.loadFeeds();
  }

  private loadFeeds(): void {
    this.isLoading.set(true);
    this.feedService
      .getFeeds()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.feeds.set(response.data ?? []);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load feed intelligence');
        },
      });
  }

  protected getScheduleLabel(schedule: string): string {
    return this.SCHEDULE_LABELS[schedule] ?? schedule;
  }
}
