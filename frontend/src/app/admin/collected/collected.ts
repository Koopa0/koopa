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
  Database,
  ThumbsUp,
  ThumbsDown,
  ExternalLink,
  Loader2,
  ChevronLeft,
  ChevronRight,
  Filter,
  RefreshCw,
  EyeOff,
} from 'lucide-angular';
import { CollectedService } from '../../core/services/collected.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  ApiCollectedItem,
  CollectedStatus,
  CollectedFeedback,
} from '../../core/models';

const ITEMS_PER_PAGE = 20;

@Component({
  selector: 'app-collected',
  standalone: true,
  imports: [DatePipe, LucideAngularModule],
  templateUrl: './collected.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CollectedComponent implements OnInit {
  private readonly collectedService = inject(CollectedService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly notificationService = inject(NotificationService);

  protected readonly items = signal<ApiCollectedItem[]>([]);
  protected readonly totalItems = signal(0);
  protected readonly currentPage = signal(1);
  protected readonly isLoading = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly statusFilter = signal<CollectedStatus | null>(null);

  protected readonly totalPages = computed(() =>
    Math.ceil(this.totalItems() / ITEMS_PER_PAGE),
  );
  protected readonly visiblePages = computed(() => {
    const total = this.totalPages();
    const current = this.currentPage();
    const windowSize = 10;
    const half = Math.floor(windowSize / 2);
    let start = Math.max(1, current - half);
    let end = start + windowSize - 1;
    if (end > total) {
      end = total;
      start = Math.max(1, end - windowSize + 1);
    }
    return Array.from({ length: end - start + 1 }, (_, i) => start + i);
  });

  // Icons
  protected readonly DatabaseIcon = Database;
  protected readonly ThumbsUpIcon = ThumbsUp;
  protected readonly ThumbsDownIcon = ThumbsDown;
  protected readonly ExternalLinkIcon = ExternalLink;
  protected readonly Loader2Icon = Loader2;
  protected readonly ChevronLeftIcon = ChevronLeft;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly FilterIcon = Filter;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly EyeOffIcon = EyeOff;

  ngOnInit(): void {
    this.loadItems();
  }

  protected loadItems(): void {
    this.isLoading.set(true);
    this.error.set(null);

    const params: Record<string, string | number> = {
      page: this.currentPage(),
      per_page: ITEMS_PER_PAGE,
    };
    const status = this.statusFilter();
    if (status) {
      params['status'] = status;
    }

    this.collectedService
      .getCollected({ page: this.currentPage(), perPage: ITEMS_PER_PAGE, status: status ?? undefined })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.items.set(response.data);
          this.totalItems.set(response.meta.total);
          this.isLoading.set(false);
        },
        error: () => {
          this.error.set('無法載入收集資料');
          this.isLoading.set(false);
        },
      });
  }

  protected onStatusFilter(status: CollectedStatus | null): void {
    this.statusFilter.set(status);
    this.currentPage.set(1);
    this.loadItems();
  }

  protected onPageChange(page: number): void {
    this.currentPage.set(page);
    this.loadItems();
  }

  protected sendFeedback(item: ApiCollectedItem, feedback: CollectedFeedback): void {
    this.collectedService
      .sendFeedback(item.id, feedback)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          // 更新本地狀態
          this.items.update((list) =>
            list.map((i) =>
              i.id === item.id ? { ...i, user_feedback: feedback } : i,
            ),
          );
        },
        error: () => this.notificationService.error('Feedback 送出失敗'),
      });
  }

  protected ignoreItem(item: ApiCollectedItem): void {
    this.collectedService
      .ignoreItem(item.id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.items.update((list) =>
            list.map((i) =>
              i.id === item.id ? { ...i, status: 'ignored' as CollectedStatus } : i,
            ),
          );
          this.notificationService.success('已忽略');
        },
        error: () => this.notificationService.error('操作失敗'),
      });
  }

  protected getScoreClass(score: number | null): string {
    if (score === null) {
      return 'border-zinc-600 bg-zinc-800 text-zinc-400';
    }
    if (score >= 70) {
      return 'border-emerald-700 bg-emerald-900/30 text-emerald-400';
    }
    if (score >= 50) {
      return 'border-amber-700 bg-amber-900/30 text-amber-400';
    }
    return 'border-red-700 bg-red-900/30 text-red-400';
  }

  protected getDisplayTitle(item: ApiCollectedItem): string {
    return item.ai_title_zh ?? item.title;
  }

  protected getDisplaySummary(item: ApiCollectedItem): string | null {
    return item.ai_summary_zh ?? item.ai_summary;
  }

}
