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
import { RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  FileText,
  RefreshCw,
  Filter,
  Loader2,
  ChevronLeft,
  ChevronRight,
  Eye,
  EyeOff,
} from 'lucide-angular';
import { ContentService } from '../../core/services/content.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  ApiContent,
  ContentType,
  ContentVisibility,
} from '../../core/models';

const ITEMS_PER_PAGE = 20;

interface FilterOption<T> {
  label: string;
  value: T | null;
}

@Component({
  selector: 'app-admin-contents',
  standalone: true,
  imports: [DatePipe, RouterLink, LucideAngularModule],
  templateUrl: './contents.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AdminContentsComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly notificationService = inject(NotificationService);

  protected readonly items = signal<ApiContent[]>([]);
  protected readonly totalItems = signal(0);
  protected readonly currentPage = signal(1);
  protected readonly isLoading = signal(false);
  protected readonly visibilityFilter = signal<ContentVisibility | null>(null);
  protected readonly typeFilter = signal<ContentType | null>(null);

  protected readonly totalPages = computed(() =>
    Math.ceil(this.totalItems() / ITEMS_PER_PAGE),
  );

  // Icons
  protected readonly FileTextIcon = FileText;
  protected readonly RefreshCwIcon = RefreshCw;
  protected readonly FilterIcon = Filter;
  protected readonly Loader2Icon = Loader2;
  protected readonly ChevronLeftIcon = ChevronLeft;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly EyeIcon = Eye;
  protected readonly EyeOffIcon = EyeOff;

  protected readonly visibilityOptions: FilterOption<ContentVisibility>[] = [
    { label: 'All', value: null },
    { label: 'Public', value: 'public' },
    { label: 'Private', value: 'private' },
  ];

  protected readonly typeOptions: FilterOption<ContentType>[] = [
    { label: 'All', value: null },
    { label: 'article', value: 'article' },
    { label: 'til', value: 'til' },
    { label: 'build-log', value: 'build-log' },
    { label: 'note', value: 'note' },
    { label: 'bookmark', value: 'bookmark' },
    { label: 'digest', value: 'digest' },
  ];

  ngOnInit(): void {
    this.loadItems();
  }

  protected loadItems(): void {
    this.isLoading.set(true);

    this.contentService
      .adminList({
        page: this.currentPage(),
        perPage: ITEMS_PER_PAGE,
        type: this.typeFilter() ?? undefined,
        visibility: this.visibilityFilter() ?? undefined,
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.items.set(response.data);
          this.totalItems.set(response.meta.total);
          this.isLoading.set(false);
        },
        error: () => {
          this.notificationService.error('無法載入內容列表');
          this.isLoading.set(false);
        },
      });
  }

  protected onVisibilityFilter(value: ContentVisibility | null): void {
    this.visibilityFilter.set(value);
    this.currentPage.set(1);
    this.loadItems();
  }

  protected onTypeFilter(value: ContentType | null): void {
    this.typeFilter.set(value);
    this.currentPage.set(1);
    this.loadItems();
  }

  protected goToPage(page: number): void {
    this.currentPage.set(page);
    this.loadItems();
  }

  protected toggleVisibility(item: ApiContent): void {
    const newVisibility: ContentVisibility =
      item.visibility === 'public' ? 'private' : 'public';

    this.contentService
      .setVisibility(item.id, newVisibility)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (updated) => {
          this.items.update((list) =>
            list.map((i) =>
              i.id === item.id ? { ...i, visibility: updated.visibility } : i,
            ),
          );
          this.notificationService.success(`已切換為 ${updated.visibility}`);
        },
        error: () => this.notificationService.error('切換 visibility 失敗'),
      });
  }
}
