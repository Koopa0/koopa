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
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  Rss,
  Plus,
  Pencil,
  Trash2,
  RefreshCw,
  Loader2,
  AlertTriangle,
  X,
  Download,
  ToggleLeft,
  ToggleRight,
} from 'lucide-angular';
import { FeedService } from '../../core/services/feed.service';
import { TopicService } from '../../core/services/topic.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  ApiFeed,
  ApiCreateFeedRequest,
  ApiUpdateFeedRequest,
  FeedSchedule,
  FeedFilterConfig,
  ApiTopic,
} from '../../core/models';

type DialogMode = 'create' | 'edit';

const SCHEDULE_LABELS: Record<FeedSchedule, string> = {
  hourly_4: 'Every 4h',
  daily: 'Daily',
  weekly: 'Weekly',
};

@Component({
  selector: 'app-feeds',
  standalone: true,
  imports: [DatePipe, LucideAngularModule],
  templateUrl: './feeds.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class FeedsComponent implements OnInit {
  private readonly feedService = inject(FeedService);
  private readonly topicService = inject(TopicService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly notificationService = inject(NotificationService);

  protected readonly feeds = signal<ApiFeed[]>([]);
  protected readonly topics = signal<ApiTopic[]>([]);
  protected readonly isLoading = signal(false);
  protected readonly error = signal<string | null>(null);

  // Dialog state
  protected readonly isDialogOpen = signal(false);
  protected readonly dialogMode = signal<DialogMode>('create');
  protected readonly editingFeed = signal<ApiFeed | null>(null);
  protected readonly isSaving = signal(false);

  // Form fields
  protected readonly formName = signal('');
  protected readonly formUrl = signal('');
  protected readonly formSchedule = signal<FeedSchedule>('daily');
  protected readonly formTopics = signal<string[]>([]);
  protected readonly formDenyPaths = signal<string[]>([]);
  protected readonly formDenyTitlePatterns = signal<string[]>([]);
  protected readonly formAllowTags = signal<string[]>([]);
  protected readonly formDenyTags = signal<string[]>([]);

  // Delete confirmation
  protected readonly deleteTarget = signal<ApiFeed | null>(null);
  protected readonly isDeleting = signal(false);

  // Fetching state per feed
  protected readonly fetchingId = signal<string | null>(null);

  protected readonly sortedFeeds = computed(() =>
    [...this.feeds()].sort((a, b) => a.name.localeCompare(b.name)),
  );

  protected readonly enabledCount = computed(
    () => this.feeds().filter((f) => f.enabled).length,
  );

  // Icons
  protected readonly RssIcon = Rss;
  protected readonly PlusIcon = Plus;
  protected readonly PencilIcon = Pencil;
  protected readonly Trash2Icon = Trash2;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly Loader2Icon = Loader2;
  protected readonly AlertTriangleIcon = AlertTriangle;
  protected readonly XIcon = X;
  protected readonly DownloadIcon = Download;
  protected readonly ToggleLeftIcon = ToggleLeft;
  protected readonly ToggleRightIcon = ToggleRight;

  ngOnInit(): void {
    this.loadFeeds();
    this.topicService
      .getAllTopics()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (list) => this.topics.set(list),
      });
  }

  protected loadFeeds(): void {
    this.isLoading.set(true);
    this.error.set(null);
    this.feedService
      .getFeeds()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (res) => {
          this.feeds.set(res.data);
          this.isLoading.set(false);
        },
        error: () => {
          this.error.set('無法載入 RSS Feeds');
          this.isLoading.set(false);
        },
      });
  }

  protected openCreateDialog(): void {
    this.dialogMode.set('create');
    this.editingFeed.set(null);
    this.formName.set('');
    this.formUrl.set('');
    this.formSchedule.set('daily');
    this.formTopics.set([]);
    this.resetFilterConfig({});
    this.isDialogOpen.set(true);
  }

  protected openEditDialog(feed: ApiFeed): void {
    this.dialogMode.set('edit');
    this.editingFeed.set(feed);
    this.formName.set(feed.name);
    this.formUrl.set(feed.url);
    this.formSchedule.set(feed.schedule);
    this.formTopics.set([...feed.topics]);
    this.resetFilterConfig(feed.filter_config);
    this.isDialogOpen.set(true);
  }

  protected closeDialog(): void {
    this.isDialogOpen.set(false);
    this.editingFeed.set(null);
  }

  protected onFormNameChange(event: Event): void {
    this.formName.set((event.target as HTMLInputElement).value);
  }

  protected onFormUrlChange(event: Event): void {
    this.formUrl.set((event.target as HTMLInputElement).value);
  }

  protected onFormScheduleChange(event: Event): void {
    this.formSchedule.set((event.target as HTMLSelectElement).value as FeedSchedule);
  }

  protected toggleFormTopic(topicName: string): void {
    const current = this.formTopics();
    if (current.includes(topicName)) {
      this.formTopics.set(current.filter((t) => t !== topicName));
    } else {
      this.formTopics.set([...current, topicName]);
    }
  }

  protected addFilterItem(field: 'denyPaths' | 'denyTitlePatterns' | 'allowTags' | 'denyTags', value: string): void {
    const trimmed = value.trim();
    if (!trimmed) {
      return;
    }
    const signalMap = {
      denyPaths: this.formDenyPaths,
      denyTitlePatterns: this.formDenyTitlePatterns,
      allowTags: this.formAllowTags,
      denyTags: this.formDenyTags,
    } as const;
    const sig = signalMap[field];
    if (!sig().includes(trimmed)) {
      sig.update((list) => [...list, trimmed]);
    }
  }

  protected removeFilterItem(field: 'denyPaths' | 'denyTitlePatterns' | 'allowTags' | 'denyTags', index: number): void {
    const signalMap = {
      denyPaths: this.formDenyPaths,
      denyTitlePatterns: this.formDenyTitlePatterns,
      allowTags: this.formAllowTags,
      denyTags: this.formDenyTags,
    } as const;
    signalMap[field].update((list) => list.filter((_, i) => i !== index));
  }

  protected onFilterKeydown(event: KeyboardEvent, field: 'denyPaths' | 'denyTitlePatterns' | 'allowTags' | 'denyTags'): void {
    if (event.key === 'Enter') {
      event.preventDefault();
      const input = event.target as HTMLInputElement;
      this.addFilterItem(field, input.value);
      input.value = '';
    }
  }

  private resetFilterConfig(config: FeedFilterConfig): void {
    this.formDenyPaths.set([...(config.deny_paths ?? [])]);
    this.formDenyTitlePatterns.set([...(config.deny_title_patterns ?? [])]);
    this.formAllowTags.set([...(config.allow_tags ?? [])]);
    this.formDenyTags.set([...(config.deny_tags ?? [])]);
  }

  private buildFilterConfig(): FeedFilterConfig {
    const config: FeedFilterConfig = {};
    if (this.formDenyPaths().length > 0) {
      config.deny_paths = this.formDenyPaths();
    }
    if (this.formDenyTitlePatterns().length > 0) {
      config.deny_title_patterns = this.formDenyTitlePatterns();
    }
    if (this.formAllowTags().length > 0) {
      config.allow_tags = this.formAllowTags();
    }
    if (this.formDenyTags().length > 0) {
      config.deny_tags = this.formDenyTags();
    }
    return config;
  }

  protected saveFeed(): void {
    if (!this.formName() || !this.formUrl()) {
      return;
    }

    this.isSaving.set(true);
    const filterConfig = this.buildFilterConfig();

    if (this.dialogMode() === 'create') {
      const body: ApiCreateFeedRequest = {
        url: this.formUrl(),
        name: this.formName(),
        schedule: this.formSchedule(),
        topics: this.formTopics(),
        filter_config: filterConfig,
      };
      this.feedService
        .createFeed(body)
        .pipe(takeUntilDestroyed(this.destroyRef))
        .subscribe({
          next: () => {
            this.isSaving.set(false);
            this.closeDialog();
            this.notificationService.success('Feed 已新增');
            this.loadFeeds();
          },
          error: () => {
            this.isSaving.set(false);
            this.notificationService.error('新增失敗');
          },
        });
    } else {
      const feed = this.editingFeed();
      if (!feed) {
        return;
      }
      const body: ApiUpdateFeedRequest = {
        url: this.formUrl(),
        name: this.formName(),
        schedule: this.formSchedule(),
        topics: this.formTopics(),
        filter_config: filterConfig,
      };
      this.feedService
        .updateFeed(feed.id, body)
        .pipe(takeUntilDestroyed(this.destroyRef))
        .subscribe({
          next: () => {
            this.isSaving.set(false);
            this.closeDialog();
            this.notificationService.success('Feed 已更新');
            this.loadFeeds();
          },
          error: () => {
            this.isSaving.set(false);
            this.notificationService.error('更新失敗');
          },
        });
    }
  }

  protected toggleEnabled(feed: ApiFeed): void {
    this.feedService
      .updateFeed(feed.id, { enabled: !feed.enabled })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.loadFeeds(),
        error: () => this.notificationService.error('切換失敗'),
      });
  }

  protected requestDelete(feed: ApiFeed): void {
    this.deleteTarget.set(feed);
  }

  protected cancelDelete(): void {
    this.deleteTarget.set(null);
  }

  protected confirmDelete(): void {
    const feed = this.deleteTarget();
    if (!feed) {
      return;
    }
    this.isDeleting.set(true);
    this.feedService
      .deleteFeed(feed.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.isDeleting.set(false);
          this.deleteTarget.set(null);
          this.notificationService.success('Feed 已刪除');
          this.loadFeeds();
        },
        error: () => {
          this.isDeleting.set(false);
          this.notificationService.error('刪除失敗');
        },
      });
  }

  protected fetchNow(feed: ApiFeed): void {
    this.fetchingId.set(feed.id);
    this.feedService
      .fetchFeed(feed.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (res) => {
          this.fetchingId.set(null);
          this.notificationService.success(
            `已抓取，新增 ${res.data.new_items} 筆`,
          );
          this.loadFeeds();
        },
        error: () => {
          this.fetchingId.set(null);
          this.notificationService.error('抓取失敗');
        },
      });
  }

  protected getScheduleLabel(schedule: FeedSchedule): string {
    return SCHEDULE_LABELS[schedule];
  }

  protected formatPattern(pattern: string): string {
    return pattern.replace(/\(\?i\)/g, '');
  }

  protected getScheduleClass(schedule: FeedSchedule): string {
    switch (schedule) {
      case 'hourly_4':
        return 'border-sky-700 bg-sky-900/30 text-sky-400';
      case 'daily':
        return 'border-emerald-700 bg-emerald-900/30 text-emerald-400';
      case 'weekly':
        return 'border-zinc-600 bg-zinc-800 text-zinc-300';
    }
  }

}
