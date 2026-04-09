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
  FileText,
  Search,
  ExternalLink,
  Filter,
} from 'lucide-angular';
import { ContentService } from '../../core/services/content.service';
import { NotificationService } from '../../core/services/notification.service';
import type { ApiContent, ContentType } from '../../core/models/api.model';

const CONTENT_TYPES: ContentType[] = [
  'article',
  'essay',
  'build-log',
  'til',
  'note',
  'bookmark',
  'digest',
];

@Component({
  selector: 'app-library',
  standalone: true,
  imports: [DatePipe, LucideAngularModule],
  templateUrl: './library.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LibraryComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly notificationService = inject(NotificationService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly items = signal<ApiContent[]>([]);
  protected readonly isLoading = signal(true);
  protected readonly selectedType = signal<ContentType | null>(null);
  protected readonly searchQuery = signal('');
  protected readonly totalCount = signal(0);

  protected readonly contentTypes = CONTENT_TYPES;

  protected readonly filteredItems = computed(() => {
    const query = this.searchQuery().toLowerCase().trim();
    const list = this.items();
    if (!query) return list;
    return list.filter(
      (item) =>
        item.title.toLowerCase().includes(query) ||
        item.slug.toLowerCase().includes(query) ||
        item.tags.some((tag) => tag.toLowerCase().includes(query)),
    );
  });

  protected readonly typeCounts = computed(() => {
    const list = this.items();
    const counts: Record<string, number> = {};
    for (const item of list) {
      counts[item.type] = (counts[item.type] ?? 0) + 1;
    }
    return counts;
  });

  // Icons
  protected readonly FileTextIcon = FileText;
  protected readonly SearchIcon = Search;
  protected readonly ExternalLinkIcon = ExternalLink;
  protected readonly FilterIcon = Filter;

  ngOnInit(): void {
    this.loadContent();
  }

  protected selectType(type: ContentType | null): void {
    this.selectedType.set(type);
    this.loadContent();
  }

  protected updateSearch(event: Event): void {
    const target = event.target as HTMLInputElement;
    this.searchQuery.set(target.value);
  }

  private loadContent(): void {
    this.isLoading.set(true);
    const type = this.selectedType();
    this.contentService
      .adminList({
        perPage: 100,
        type: type ?? undefined,
        is_public: true,
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.items.set(response.data);
          this.totalCount.set(response.meta.total);
          this.isLoading.set(false);
        },
        error: () => {
          this.isLoading.set(false);
          this.notificationService.error('Failed to load content library');
        },
      });
  }

  protected getTypeBadgeColor(type: ContentType): string {
    switch (type) {
      case 'article':
        return 'bg-sky-500/20 text-sky-400';
      case 'essay':
        return 'bg-violet-500/20 text-violet-400';
      case 'build-log':
        return 'bg-amber-500/20 text-amber-400';
      case 'til':
        return 'bg-emerald-500/20 text-emerald-400';
      case 'note':
        return 'bg-zinc-500/20 text-zinc-400';
      case 'bookmark':
        return 'bg-orange-500/20 text-orange-400';
      case 'digest':
        return 'bg-rose-500/20 text-rose-400';
      default:
        return 'bg-zinc-500/20 text-zinc-400';
    }
  }

  protected getPublicUrl(item: ApiContent): string {
    switch (item.type) {
      case 'article':
        return `/articles/${item.slug}`;
      case 'build-log':
        return `/build-logs/${item.slug}`;
      case 'til':
        return `/til/${item.slug}`;
      case 'note':
        return `/notes/${item.slug}`;
      default:
        return `/contents/${item.slug}`;
    }
  }
}
