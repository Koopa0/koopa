import {
  Component,
  ChangeDetectionStrategy,
  DestroyRef,
  OnInit,
  PLATFORM_ID,
  inject,
  signal,
  computed,
} from '@angular/core';
import { isPlatformBrowser, DatePipe } from '@angular/common';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Subject, debounceTime } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  Search,
  X,
  ChevronLeft,
  ChevronRight,
  FileText,
} from 'lucide-angular';
import { ContentService } from '../../core/services/content.service';
import {
  CONTENT_TYPE_CONFIG,
  contentTypeRoute,
  publicContentTypes,
} from '../../core/models';
import type { ApiContent, ContentType, ApiPaginationMeta } from '../../core/models';

const RESULTS_PER_PAGE = 12;
const SEARCH_DEBOUNCE_MS = 300;

@Component({
  selector: 'app-search',
  standalone: true,
  imports: [RouterLink, DatePipe, LucideAngularModule],
  templateUrl: './search.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SearchComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly contentService = inject(ContentService);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly destroyRef = inject(DestroyRef);

  private readonly searchSubject = new Subject<string>();

  protected readonly query = signal('');
  protected readonly typeFilter = signal<ContentType | null>(null);
  protected readonly results = signal<ApiContent[]>([]);
  protected readonly meta = signal<ApiPaginationMeta | null>(null);
  protected readonly currentPage = signal(1);
  protected readonly isLoading = signal(false);
  protected readonly error = signal<string | null>(null);

  protected readonly typeConfig = CONTENT_TYPE_CONFIG;
  protected readonly availableTypes = publicContentTypes();

  protected readonly totalPages = computed(() => {
    const m = this.meta();
    return m ? m.total_pages : 0;
  });

  protected readonly pageArray = computed(() =>
    Array.from({ length: this.totalPages() }, (_, i) => i + 1),
  );

  protected readonly SearchIcon = Search;
  protected readonly XIcon = X;
  protected readonly ChevronLeftIcon = ChevronLeft;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly FileTextIcon = FileText;

  constructor() {
    this.searchSubject
      .pipe(debounceTime(SEARCH_DEBOUNCE_MS), takeUntilDestroyed())
      .subscribe((q) => {
        this.query.set(q);
        this.currentPage.set(1);
        this.updateUrl();
        this.executeSearch();
      });
  }

  ngOnInit(): void {
    this.route.queryParams
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((params) => {
        const q = (params['q'] as string) ?? '';
        const type = (params['type'] as ContentType) ?? null;
        const page = Number(params['page']) || 1;

        this.query.set(q);
        this.typeFilter.set(type && this.availableTypes.includes(type) ? type : null);
        this.currentPage.set(page);

        if (q.trim().length >= 2) {
          this.executeSearch();
        }
      });
  }

  protected onInput(event: Event): void {
    const value = (event.target as HTMLInputElement).value;
    this.searchSubject.next(value);
  }

  protected clearSearch(): void {
    this.query.set('');
    this.results.set([]);
    this.meta.set(null);
    this.typeFilter.set(null);
    this.currentPage.set(1);
    this.updateUrl();
  }

  protected selectType(type: ContentType | null): void {
    this.typeFilter.set(type);
    this.currentPage.set(1);
    this.updateUrl();
    this.executeSearch();
  }

  protected onPageChange(page: number): void {
    this.currentPage.set(page);
    this.updateUrl();
    this.executeSearch();
    if (isPlatformBrowser(this.platformId)) {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }

  protected getResultRoute(result: ApiContent): string {
    return `${contentTypeRoute(result.type)}/${result.slug}`;
  }

  private executeSearch(): void {
    const q = this.query().trim();
    if (q.length < 2) {
      this.results.set([]);
      this.meta.set(null);
      return;
    }

    this.isLoading.set(true);
    this.error.set(null);

    this.contentService
      .search(q, {
        page: this.currentPage(),
        perPage: RESULTS_PER_PAGE,
        type: this.typeFilter() ?? undefined,
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (res) => {
          this.results.set(res.data);
          this.meta.set(res.meta);
          this.isLoading.set(false);
        },
        error: () => {
          this.error.set('搜尋時發生錯誤，請稍後再試。');
          this.isLoading.set(false);
        },
      });
  }

  private updateUrl(): void {
    const queryParams: Record<string, string | number | null> = {};
    const q = this.query().trim();
    if (q) queryParams['q'] = q;
    const type = this.typeFilter();
    if (type) queryParams['type'] = type;
    const page = this.currentPage();
    if (page > 1) queryParams['page'] = page;

    this.router.navigate([], {
      relativeTo: this.route,
      queryParams,
      replaceUrl: true,
    });
  }
}
