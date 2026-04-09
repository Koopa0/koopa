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
import { DatePipe, DecimalPipe } from '@angular/common';
import {
  LucideAngularModule,
  Inbox,
  ExternalLink,
  ThumbsUp,
  ThumbsDown,
  EyeOff,
  ChevronLeft,
  ChevronRight,
} from 'lucide-angular';
import {
  CollectedService,
  type CollectedFilters,
} from '../../core/services/collected.service';
import { NotificationService } from '../../core/services/notification.service';
import { StatusBadgeComponent } from '../../shared/components/status-badge/status-badge.component';
import type {
  ApiCollectedItem,
  CollectedStatus,
  CollectedFeedback,
} from '../../core/models';

const STATUS_VALUES: CollectedStatus[] = [
  'unread',
  'read',
  'curated',
  'ignored',
];

const PER_PAGE = 25;

@Component({
  selector: 'app-collected',
  standalone: true,
  imports: [DatePipe, DecimalPipe, LucideAngularModule, StatusBadgeComponent],
  templateUrl: './collected.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CollectedComponent implements OnInit {
  private readonly collectedService = inject(CollectedService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly items = signal<ApiCollectedItem[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly selectedStatus = signal<CollectedStatus | null>(null);
  protected readonly page = signal(1);
  protected readonly total = signal(0);
  protected readonly totalPages = signal(1);

  protected readonly statusValues = STATUS_VALUES;
  protected readonly perPage = PER_PAGE;

  protected readonly hasPrev = computed(() => this.page() > 1);
  protected readonly hasNext = computed(() => this.page() < this.totalPages());
  protected readonly rangeStart = computed(() =>
    this.total() === 0 ? 0 : (this.page() - 1) * this.perPage + 1,
  );
  protected readonly rangeEnd = computed(() =>
    Math.min(this.page() * this.perPage, this.total()),
  );

  // Icons
  protected readonly InboxIcon = Inbox;
  protected readonly ExternalLinkIcon = ExternalLink;
  protected readonly ThumbsUpIcon = ThumbsUp;
  protected readonly ThumbsDownIcon = ThumbsDown;
  protected readonly EyeOffIcon = EyeOff;
  protected readonly ChevronLeftIcon = ChevronLeft;
  protected readonly ChevronRightIcon = ChevronRight;

  ngOnInit(): void {
    this.loadItems();
  }

  protected selectStatus(status: CollectedStatus | null): void {
    this.selectedStatus.set(status);
    this.page.set(1);
    this.loadItems();
  }

  protected goPrev(): void {
    if (!this.hasPrev()) return;
    this.page.update((p) => p - 1);
    this.loadItems();
  }

  protected goNext(): void {
    if (!this.hasNext()) return;
    this.page.update((p) => p + 1);
    this.loadItems();
  }

  protected sendFeedback(
    item: ApiCollectedItem,
    feedback: CollectedFeedback,
  ): void {
    this.collectedService
      .sendFeedback(item.id, feedback)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.items.update((list) =>
            list.map((i) =>
              i.id === item.id
                ? {
                    ...i,
                    user_feedback: feedback,
                    feedback_at: new Date().toISOString(),
                  }
                : i,
            ),
          );
        },
        error: () => {
          this.notificationService.error('Failed to send feedback');
        },
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
              i.id === item.id ? { ...i, status: 'ignored' } : i,
            ),
          );
          this.notificationService.success('Item ignored');
        },
        error: () => {
          this.notificationService.error('Failed to ignore item');
        },
      });
  }

  protected getStatusVariant(
    status: CollectedStatus,
  ): 'success' | 'warning' | 'info' | 'danger' | 'neutral' {
    switch (status) {
      case 'unread':
        return 'info';
      case 'read':
        return 'neutral';
      case 'curated':
        return 'success';
      case 'ignored':
        return 'warning';
      default:
        return 'neutral';
    }
  }

  private loadItems(): void {
    this.isLoading.set(true);
    const filters: CollectedFilters = {
      page: this.page(),
      perPage: this.perPage,
    };
    const status = this.selectedStatus();
    if (status) {
      filters.status = status;
    }

    this.collectedService
      .getCollected(filters)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.items.set(response.data);
          this.total.set(response.meta.total);
          this.totalPages.set(Math.max(response.meta.total_pages, 1));
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load collected items');
        },
      });
  }
}
