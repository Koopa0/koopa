import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  provideHttpClientTesting,
  HttpTestingController,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { ArticlesComponent } from './articles';
import type { ApiContent, ApiPaginationMeta } from '../../core/models';

function buildMockArticle(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'test-1',
    slug: 'test-article',
    title: 'Test Article',
    excerpt: 'A test excerpt',
    body: '',
    type: 'article',
    status: 'published',
    tags: ['angular', 'testing'],
    topics: [],
    cover_image: null,
    source: null,
    source_type: null,
    series_id: null,
    series_order: null,
    review_level: 'auto',
    ai_metadata: null,
    reading_time: 5,
    published_at: '2026-01-15T00:00:00Z',
    created_at: '2026-01-15T00:00:00Z',
    updated_at: '2026-01-15T00:00:00Z',
    ...overrides,
  };
}

function buildMockMeta(overrides: Partial<ApiPaginationMeta> = {}): ApiPaginationMeta {
  return {
    total: 1,
    page: 1,
    per_page: 12,
    total_pages: 1,
    ...overrides,
  };
}

describe('ArticlesComponent', () => {
  let component: ArticlesComponent;
  let fixture: ComponentFixture<ArticlesComponent>;
  let httpTesting: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ArticlesComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpTesting = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(ArticlesComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpTesting.verify();
  });

  it('should create', () => {
    fixture.detectChanges();
    const req = httpTesting.expectOne((r) =>
      r.url.includes('/api/contents') && r.method === 'GET',
    );
    req.flush({ data: [], meta: buildMockMeta({ total: 0 }) });
    expect(component).toBeTruthy();
  });

  it('should fetch articles on init and populate articles signal', () => {
    const mockArticles = [
      buildMockArticle({ id: '1', title: 'First' }),
      buildMockArticle({ id: '2', title: 'Second' }),
    ];

    fixture.detectChanges();

    const req = httpTesting.expectOne((r) =>
      r.url.includes('/api/contents') && r.method === 'GET',
    );
    req.flush({ data: mockArticles, meta: buildMockMeta({ total: 2 }) });
    fixture.detectChanges();

    expect(component['articles']()).toHaveLength(2);
    expect(component['totalArticles']()).toBe(2);
    expect(component['isLoading']()).toBe(false);
  });

  it('should display articles in the template after loading', () => {
    const mockArticles = [
      buildMockArticle({ id: '1', title: 'Angular Signals Guide', slug: 'angular-signals' }),
    ];

    fixture.detectChanges();

    const req = httpTesting.expectOne((r) =>
      r.url.includes('/api/contents') && r.method === 'GET',
    );
    req.flush({ data: mockArticles, meta: buildMockMeta({ total: 1 }) });
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Angular Signals Guide');
  });

  it('should set error signal when HTTP request fails', () => {
    fixture.detectChanges();

    const req = httpTesting.expectOne((r) =>
      r.url.includes('/api/contents') && r.method === 'GET',
    );
    req.flush('Server error', { status: 500, statusText: 'Internal Server Error' });
    fixture.detectChanges();

    expect(component['error']()).toBe('Failed to load articles. Please try again later.');
    expect(component['isLoading']()).toBe(false);
  });

  it('should show empty state when no articles returned', () => {
    fixture.detectChanges();

    const req = httpTesting.expectOne((r) =>
      r.url.includes('/api/contents') && r.method === 'GET',
    );
    req.flush({ data: [], meta: buildMockMeta({ total: 0 }) });
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('No articles found');
  });

  it('should show loading skeletons while fetching', () => {
    fixture.detectChanges();

    expect(component['isLoading']()).toBe(true);
    const el = fixture.nativeElement as HTMLElement;
    const skeletons = el.querySelectorAll('app-skeleton');
    expect(skeletons.length).toBeGreaterThan(0);

    const req = httpTesting.expectOne((r) =>
      r.url.includes('/api/contents') && r.method === 'GET',
    );
    req.flush({ data: [], meta: buildMockMeta({ total: 0 }) });
  });

  it('should compute totalPages correctly', () => {
    fixture.detectChanges();

    const req = httpTesting.expectOne((r) =>
      r.url.includes('/api/contents') && r.method === 'GET',
    );
    req.flush({ data: [], meta: buildMockMeta({ total: 25 }) });
    fixture.detectChanges();

    // 25 articles / 12 per page = 3 pages
    expect(component['totalPages']()).toBe(3);
  });

  it('should clear filters and reload articles', () => {
    fixture.detectChanges();

    // Initial load
    const initialReq = httpTesting.expectOne((r) =>
      r.url.includes('/api/contents') && r.method === 'GET',
    );
    initialReq.flush({ data: [], meta: buildMockMeta({ total: 0 }) });

    // Trigger clearFilters
    component['clearFilters']();

    const reloadReq = httpTesting.expectOne((r) =>
      r.url.includes('/api/contents') && r.method === 'GET',
    );
    reloadReq.flush({ data: [], meta: buildMockMeta({ total: 0 }) });

    expect(component['searchQuery']()).toBe('');
    expect(component['currentPage']()).toBe(1);
  });

  it('should change page and reload articles', () => {
    fixture.detectChanges();

    const initialReq = httpTesting.expectOne((r) =>
      r.url.includes('/api/contents') && r.method === 'GET',
    );
    initialReq.flush({
      data: Array.from({ length: 12 }, (_, i) => buildMockArticle({ id: `a${i}` })),
      meta: buildMockMeta({ total: 24 }),
    });

    component['onPageChange'](2);

    const pageReq = httpTesting.expectOne((r) =>
      r.url.includes('/api/contents') && r.method === 'GET',
    );
    pageReq.flush({
      data: Array.from({ length: 12 }, (_, i) => buildMockArticle({ id: `b${i}` })),
      meta: buildMockMeta({ total: 24, page: 2 }),
    });

    expect(component['currentPage']()).toBe(2);
  });
});
