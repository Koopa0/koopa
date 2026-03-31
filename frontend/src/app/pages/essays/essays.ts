import {
  Component,
  DestroyRef,
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
import { environment } from '../../../environments/environment';
import { ContentService } from '../../core/services/content.service';
import { SkeletonComponent } from '../../shared/skeleton/skeleton.component';
import { SeoService } from '../../core/services/seo/seo.service';
import { buildCollectionPageSchema } from '../../core/services/seo/json-ld.util';
import type { ApiContent } from '../../core/models';

const ESSAYS_PER_PAGE = 12;
const SEARCH_DEBOUNCE_MS = 300;

@Component({
  selector: 'app-essays',
  standalone: true,
  imports: [
    RouterLink,
    DatePipe,
    FormsModule,
    LucideAngularModule,
    SkeletonComponent,
  ],
  templateUrl: './essays.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class EssaysComponent implements OnInit {
  private readonly contentService = inject(ContentService);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly seoService = inject(SeoService);
  private readonly destroyRef = inject(DestroyRef);

  private readonly searchSubject = new Subject<string>();

  protected readonly essays = signal<ApiContent[]>([]);
  protected readonly totalEssays = signal(0);
  protected readonly currentPage = signal(1);
  protected readonly isLoading = signal(false);
  protected readonly error = signal<string | null>(null);

  protected readonly searchQuery = signal('');

  protected readonly totalPages = computed(() =>
    Math.ceil(this.totalEssays() / ESSAYS_PER_PAGE),
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
        this.loadEssays();
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
      title: 'Essays',
      description: 'Personal reflections, thoughts, and non-technical essays.',
      ogUrl: `${environment.siteUrl}/essays`,
      jsonLd: buildCollectionPageSchema({
        name: 'Essays',
        description: 'Personal reflections, thoughts, and non-technical essays.',
        url: `${environment.siteUrl}/essays`,
      }),
    });
    this.loadEssays();
  }

  protected loadEssays(): void {
    this.isLoading.set(true);
    this.error.set(null);

    this.contentService
      .listByType('essay', {
        page: this.currentPage(),
        perPage: ESSAYS_PER_PAGE,
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.essays.set(response.data);
          this.totalEssays.set(response.meta.total);
          this.isLoading.set(false);
        },
        error: () => {
          this.error.set('Failed to load essays. Please try again later.');
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
    this.loadEssays();
    if (isPlatformBrowser(this.platformId)) {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }

  protected clearFilters(): void {
    this.searchQuery.set('');
    this.currentPage.set(1);
    this.loadEssays();
  }
}
