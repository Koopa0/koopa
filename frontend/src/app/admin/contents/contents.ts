import {
  Component,
  ChangeDetectionStrategy,
  inject,
  signal,
  computed,
  OnInit,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { rxResource } from '@angular/core/rxjs-interop';
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
  X,
  ExternalLink,
  Clock,
  Tag,
  BookOpen,
  Globe,
  Lock,
  Calendar,
} from 'lucide-angular';
import { ContentService } from '../../core/services/content.service';
import { NotificationService } from '../../core/services/notification.service';
import type {
  ApiContent,
  ApiListResponse,
  ContentType,
} from '../../core/models';

const ITEMS_PER_PAGE = 20;

interface FilterOption<T> {
  label: string;
  value: T | null;
}

interface ContentRequest {
  page: number;
  perPage: number;
  type?: ContentType;
  is_public?: boolean;
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
  private readonly notificationService = inject(NotificationService);
  private readonly route = inject(ActivatedRoute);

  protected readonly currentPage = signal(1);
  protected readonly visibilityFilter = signal<boolean | null>(null);
  protected readonly typeFilter = signal<ContentType | null>(null);
  protected readonly selectedItem = signal<ApiContent | null>(null);

  private readonly contentsResource = rxResource<
    ApiListResponse<ApiContent>,
    ContentRequest
  >({
    params: () => ({
      page: this.currentPage(),
      perPage: ITEMS_PER_PAGE,
      type: this.typeFilter() ?? undefined,
      is_public: this.visibilityFilter() ?? undefined,
    }),
    stream: ({ params }) => this.contentService.adminList(params),
  });

  protected readonly items = computed(() => {
    const data = this.contentsResource.value()?.data ?? [];
    // Backend AdminList doesn't populate tags/topics — normalize nulls to empty arrays
    return data.map((item) => ({
      ...item,
      tags: item.tags ?? [],
      topics: item.topics ?? [],
    }));
  });
  protected readonly totalItems = computed(
    () => this.contentsResource.value()?.meta.total ?? 0,
  );
  protected readonly isLoading = computed(() =>
    this.contentsResource.isLoading(),
  );
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
  protected readonly XIcon = X;
  protected readonly ExternalLinkIcon = ExternalLink;
  protected readonly ClockIcon = Clock;
  protected readonly TagIcon = Tag;
  protected readonly BookOpenIcon = BookOpen;
  protected readonly GlobeIcon = Globe;
  protected readonly LockIcon = Lock;
  protected readonly CalendarIcon = Calendar;

  protected readonly visibilityOptions: FilterOption<boolean>[] = [
    { label: 'All', value: null },
    { label: 'Public', value: true },
    { label: 'Private', value: false },
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
    const typeParam = this.route.snapshot.queryParamMap.get(
      'type',
    ) as ContentType | null;
    if (typeParam && this.typeOptions.some((o) => o.value === typeParam)) {
      this.typeFilter.set(typeParam);
    }
  }

  protected reload(): void {
    this.contentsResource.reload();
  }

  protected onVisibilityFilter(value: boolean | null): void {
    this.visibilityFilter.set(value);
    this.currentPage.set(1);
    this.selectedItem.set(null);
  }

  protected onTypeFilter(value: ContentType | null): void {
    this.typeFilter.set(value);
    this.currentPage.set(1);
    this.selectedItem.set(null);
  }

  protected goToPage(page: number): void {
    this.currentPage.set(page);
    this.selectedItem.set(null);
  }

  protected selectItem(item: ApiContent): void {
    this.selectedItem.update((prev) => (prev?.id === item.id ? null : item));
  }

  protected closeDetail(): void {
    this.selectedItem.set(null);
  }

  protected toggleVisibility(item: ApiContent, event: Event): void {
    event.stopPropagation();
    const newIsPublic = !item.is_public;

    this.contentService.setVisibility(item.id, newIsPublic).subscribe({
      next: (updated) => {
        this.contentsResource.reload();
        if (this.selectedItem()?.id === item.id) {
          this.selectedItem.set({ ...item, is_public: updated.is_public });
        }
        this.notificationService.success(
          `已切換為 ${updated.is_public ? 'public' : 'private'}`,
        );
      },
      error: () => this.notificationService.error('切換 visibility 失敗'),
    });
  }

  protected statusColor(status: string): string {
    switch (status) {
      case 'published':
        return 'bg-emerald-900/30 text-emerald-400';
      case 'draft':
        return 'bg-zinc-800 text-zinc-400';
      case 'review':
        return 'bg-amber-900/30 text-amber-400';
      case 'archived':
        return 'bg-zinc-800 text-zinc-500';
      default:
        return 'bg-zinc-800 text-zinc-400';
    }
  }
}
