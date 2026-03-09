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
  X,
  Clock,
  Calendar,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  FileText,
} from 'lucide-angular';
import {
  ArticleService,
  ArticlesResponse,
  ArticleFilters,
} from '../../core/services/article.service';
import { SkeletonComponent } from '../../shared/skeleton/skeleton.component';
import { fadeInUp } from '../../shared/animations/fade-in.animation';
import { SeoService } from '../../core/services/seo/seo.service';
import type { ApiContent } from '../../core/models';

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
  private readonly platformId = inject(PLATFORM_ID);
  private readonly seoService = inject(SeoService);

  private readonly searchSubject = new Subject<string>();

  protected readonly articles = signal<ApiContent[]>([]);
  protected readonly totalArticles = signal(0);
  protected readonly currentPage = signal(1);
  protected readonly isLoading = signal(false);
  protected readonly error = signal<string | null>(null);

  protected readonly searchQuery = signal('');

  protected readonly totalPages = computed(() =>
    Math.ceil(this.totalArticles() / ARTICLES_PER_PAGE),
  );
  protected readonly hasFilters = computed(
    () => this.searchQuery().length > 0,
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

  protected readonly SearchIcon = Search;
  protected readonly XIcon = X;
  protected readonly ClockIcon = Clock;
  protected readonly CalendarIcon = Calendar;
  protected readonly ArrowRightIcon = ArrowRight;
  protected readonly ChevronLeftIcon = ChevronLeft;
  protected readonly ChevronRightIcon = ChevronRight;
  protected readonly FileTextIcon = FileText;

  ngOnInit(): void {
    this.seoService.updateMeta({
      title: 'Articles',
      description: 'Technical articles, dev notes, and lessons learned.',
      ogUrl: 'https://koopa0.dev/articles',
    });
    this.loadArticles();
  }

  protected loadArticles(): void {
    this.isLoading.set(true);
    this.error.set(null);

    const filters: ArticleFilters = {
      search: this.searchQuery() || undefined,
      page: this.currentPage(),
      perPage: ARTICLES_PER_PAGE,
    };

    this.articleService.getArticles(filters).subscribe({
      next: (response: ArticlesResponse) => {
        this.articles.set(response.articles);
        this.totalArticles.set(response.meta.total);
        this.isLoading.set(false);
      },
      error: () => {
        this.error.set('Failed to load articles. Please try again later.');
        this.isLoading.set(false);
      },
    });
  }

  protected onSearchChange(event: Event): void {
    const target = event.target as HTMLInputElement;
    this.searchSubject.next(target.value);
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
    this.currentPage.set(1);
    this.loadArticles();
  }
}
