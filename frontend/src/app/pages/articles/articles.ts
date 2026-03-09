import {
  Component,
  inject,
  signal,
  computed,
  ChangeDetectionStrategy,
  OnInit,
  PLATFORM_ID,
} from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subject, debounceTime } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  Search,
  ArrowUpDown,
  X,
  Clock,
  Eye,
  Calendar,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  FileText,
} from 'lucide-angular';
import { ArticleService } from '../../core/services/article.service';
import { SkeletonComponent } from '../../shared/skeleton/skeleton.component';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import { TagService } from '../../core/services/tag.service';
import { SeoService } from '../../core/services/seo/seo.service';
import {
  ArticleListItem,
  ArticleFilters,
  ArticlesResponse,
} from '../../core/models';

const ARTICLES_PER_PAGE = 12;
const SEARCH_DEBOUNCE_MS = 300;

@Component({
  selector: 'app-articles',
  standalone: true,
  imports: [
    RouterLink,
    DatePipe,
    FormsModule,
    LucideAngularModule,
    SkeletonComponent,
  ],
  templateUrl: './articles.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  animations: [fadeInUp],
  host: { '[@fadeInUp]': '' },
})
export class ArticlesComponent implements OnInit {
  private readonly articleService = inject(ArticleService);
  private readonly tagService = inject(TagService);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly seoService = inject(SeoService);

  private readonly searchSubject = new Subject<string>();

  protected readonly articles = signal<ArticleListItem[]>([]);
  protected readonly totalArticles = signal(0);
  protected readonly currentPage = signal(1);
  protected readonly isLoading = signal(false);
  protected readonly error = signal<string | null>(null);

  protected readonly searchQuery = signal('');
  protected readonly selectedTags = signal<string[]>([]);
  protected readonly sortBy = signal<'publishedAt' | 'viewCount' | 'title'>(
    'publishedAt',
  );
  protected readonly sortOrder = signal<'asc' | 'desc'>('desc');

  protected readonly totalPages = computed(() =>
    Math.ceil(this.totalArticles() / ARTICLES_PER_PAGE),
  );
  protected readonly hasFilters = computed(
    () => this.searchQuery().length > 0 || this.selectedTags().length > 0,
  );
  protected readonly pageArray = computed(() =>
    Array.from({ length: this.totalPages() }, (_, i) => i + 1),
  );

  constructor() {
    this.searchSubject
      .pipe(debounceTime(SEARCH_DEBOUNCE_MS), takeUntilDestroyed())
      .subscribe((query) => {
        this.searchQuery.set(query);
        this.currentPage.set(1);
        this.loadArticles();
      });
  }

  protected readonly availableTags = this.tagService.tagList;
  protected readonly sortOptions = [
    { value: 'publishedAt', label: '發布日期' },
    { value: 'viewCount', label: '瀏覽次數' },
    { value: 'title', label: '標題' },
  ];

  protected readonly SearchIcon = Search;
  protected readonly ArrowUpDownIcon = ArrowUpDown;
  protected readonly XIcon = X;
  protected readonly ClockIcon = Clock;
  protected readonly EyeIcon = Eye;
  protected readonly CalendarIcon = Calendar;
  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly ChevronLeftIcon = ChevronLeft;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly FileTextIcon = FileText;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: '文章列表',
      description: '技術文章、開發筆記與學習心得',
      ogUrl: 'https://koopa0.dev/articles',
    });
    this.tagService.getAllTags().subscribe({
      error: () => {
        this.error.set('載入標籤失敗');
      },
    });
    this.loadArticles();
  }

  protected loadArticles(): void {
    this.isLoading.set(true);
    this.error.set(null);

    const filters: ArticleFilters = {
      search: this.searchQuery() || undefined,
      tags: this.selectedTags().length > 0 ? this.selectedTags() : undefined,
      sortBy: this.sortBy(),
      sortOrder: this.sortOrder(),
      page: this.currentPage(),
      limit: ARTICLES_PER_PAGE,
    };

    this.articleService.getArticles(filters).subscribe({
      next: (response: ArticlesResponse) => {
        this.articles.set(response.articles);
        this.totalArticles.set(response.total);
        this.isLoading.set(false);
      },
      error: () => {
        this.error.set('載入文章失敗，請稍後再試');
        this.isLoading.set(false);
      },
    });
  }

  protected onSearchChange(event: Event): void {
    const target = event.target as HTMLInputElement;
    this.searchSubject.next(target.value);
  }

  protected onTagToggle(tagName: string): void {
    const current = this.selectedTags();
    if (current.includes(tagName)) {
      this.selectedTags.set(current.filter((tag) => tag !== tagName));
    } else {
      this.selectedTags.set([...current, tagName]);
    }
    this.currentPage.set(1);
    this.loadArticles();
  }

  protected onSortChange(): void {
    this.currentPage.set(1);
    this.loadArticles();
  }

  protected onPageChange(page: number): void {
    this.currentPage.set(page);
    this.loadArticles();
    if (isPlatformBrowser(this.platformId)) {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }

  protected clearFilters(): void {
    this.searchQuery.set('');
    this.selectedTags.set([]);
    this.sortBy.set('publishedAt');
    this.sortOrder.set('desc');
    this.currentPage.set(1);
    this.loadArticles();
  }

  protected toggleSortOrder(): void {
    this.sortOrder.set(this.sortOrder() === 'asc' ? 'desc' : 'asc');
    this.onSortChange();
  }
}
