import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
  DestroyRef,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  Activity,
  Clock,
  Calendar,
  RefreshCw,
  ChevronDown,
  ChevronRight,
} from 'lucide-angular';
import { ActivityService } from '../../core/services/activity.service';
import { NotificationService } from '../../core/services/notification.service';
import {
  PageHeaderComponent,
  EmptyStateComponent,
  LoadingSpinnerComponent,
  StatusBadgeComponent,
} from '../../shared/components';
import type { ApiSession, ApiChangelogDay } from '../../core/models';

type ActiveTab = 'sessions' | 'changelog';

const SOURCE_CLASSES: Record<string, string> = {
  github: 'border-zinc-600 bg-zinc-800 text-zinc-300',
  obsidian: 'border-violet-800 bg-violet-900/30 text-violet-400',
  notion: 'border-sky-800 bg-sky-900/30 text-sky-400',
  rss: 'border-amber-800 bg-amber-900/30 text-amber-400',
  manual: 'border-emerald-800 bg-emerald-900/30 text-emerald-400',
};

const DEFAULT_SOURCE_CLASS = 'border-zinc-700 bg-zinc-800 text-zinc-400';

@Component({
  selector: 'app-activity',
  standalone: true,
  imports: [
    DatePipe,
    FormsModule,
    LucideAngularModule,
    PageHeaderComponent,
    EmptyStateComponent,
    LoadingSpinnerComponent,
    StatusBadgeComponent,
  ],
  templateUrl: './activity.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ActivityComponent implements OnInit {
  private readonly activityService = inject(ActivityService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly activeTab = signal<ActiveTab>('sessions');

  // ─── Sessions ───
  protected readonly sessions = signal<ApiSession[]>([]);
  protected readonly isLoadingSessions = signal(false);
  protected readonly sessionDays = signal(7);

  protected readonly totalSessionTime = computed(() => {
    const all = this.sessions();
    return all.reduce((sum, s) => sum + s.event_count, 0);
  });

  // ─── Changelog ───
  protected readonly changelog = signal<ApiChangelogDay[]>([]);
  protected readonly isLoadingChangelog = signal(false);
  protected readonly changelogDays = signal(30);
  protected readonly expandedDates = signal<Set<string>>(new Set());

  protected readonly totalEvents = computed(() =>
    this.changelog().reduce((sum, d) => sum + d.event_count, 0),
  );

  // ─── Icons ───
  protected readonly ActivityIcon = Activity;
  protected readonly ClockIcon = Clock;
  protected readonly CalendarIcon = Calendar;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly ChevronDownIcon = ChevronDown;
  protected readonly ChevronRightIcon = ChevronRight;

  ngOnInit(): void {
    this.loadSessions();
  }

  protected switchTab(tab: ActiveTab): void {
    this.activeTab.set(tab);
    if (tab === 'changelog' && this.changelog().length === 0) {
      this.loadChangelog();
    }
  }

  // ─── Sessions ───

  protected loadSessions(): void {
    this.isLoadingSessions.set(true);
    this.activityService
      .getSessions(this.sessionDays())
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.sessions.set(data);
          this.isLoadingSessions.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入 Sessions');
          this.isLoadingSessions.set(false);
        },
      });
  }

  protected updateSessionDays(days: number): void {
    this.sessionDays.set(days);
    this.loadSessions();
  }

  // ─── Changelog ───

  protected loadChangelog(): void {
    this.isLoadingChangelog.set(true);
    this.activityService
      .getChangelog(this.changelogDays())
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => {
          this.changelog.set(data);
          this.isLoadingChangelog.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入 Changelog');
          this.isLoadingChangelog.set(false);
        },
      });
  }

  protected updateChangelogDays(days: number): void {
    this.changelogDays.set(days);
    this.loadChangelog();
  }

  protected toggleDate(date: string): void {
    this.expandedDates.update((set) => {
      const next = new Set(set);
      if (next.has(date)) {
        next.delete(date);
      } else {
        next.add(date);
      }
      return next;
    });
  }

  protected isDateExpanded(date: string): boolean {
    return this.expandedDates().has(date);
  }

  protected getSourceClass(source: string): string {
    return SOURCE_CLASSES[source] ?? DEFAULT_SOURCE_CLASS;
  }

  /** 從 duration 字串取得可讀格式（Go format: "1h30m0s"） */
  protected formatDuration(duration: string): string {
    const hourMatch = duration.match(/(\d+)h/);
    const minMatch = duration.match(/(\d+)m/);
    const hours = hourMatch ? parseInt(hourMatch[1], 10) : 0;
    const mins = minMatch ? parseInt(minMatch[1], 10) : 0;
    if (hours > 0 && mins > 0) {
      return `${hours}h ${mins}m`;
    }
    if (hours > 0) {
      return `${hours}h`;
    }
    return `${mins}m`;
  }
}
