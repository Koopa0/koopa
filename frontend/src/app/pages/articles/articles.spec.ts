import {
  ComponentFixture,
  DeferBlockState,
  TestBed,
} from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  provideHttpClientTesting,
  HttpTestingController,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { Title } from '@angular/platform-browser';
import { ArticlesComponent } from './articles';
import type { ApiContent, ApiPaginationMeta } from '../../core/models';

function buildMockContent(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'test-1',
    slug: 'test-article',
    title: 'Test Article',
    excerpt: 'A test excerpt',
    body: '',
    type: 'article',
    status: 'published',
    topics: [],
    cover_image: null,
    series_id: null,
    series_order: null,
    is_public: true,
    reading_time_min: 5,
    published_at: '2026-01-15T00:00:00Z',
    created_at: '2026-01-15T00:00:00Z',
    updated_at: '2026-01-15T00:00:00Z',
    ...overrides,
  };
}

function buildMockMeta(
  overrides: Partial<ApiPaginationMeta> = {},
): ApiPaginationMeta {
  return {
    total: 1,
    page: 1,
    per_page: 50,
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
        provideHttpClient(withXhr()),
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

  /** Flush effects + microtasks so rxResource issues its requests. */
  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  /** Force the deferred list block into its rendered state so the inner
   *  loading / list / empty branch shows for the current signal values. */
  async function renderList(): Promise<void> {
    const blocks = await fixture.getDeferBlocks();
    await blocks[0].render(DeferBlockState.Complete);
    fixture.detectChanges();
  }

  function flushContents(
    contents: ApiContent[],
    meta: ApiPaginationMeta = buildMockMeta({ total: contents.length }),
  ): void {
    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/contents') && r.method === 'GET',
    );
    req.flush({ data: contents, meta });
  }

  it('should create', async () => {
    await settle();
    flushContents([]);
    expect(component).toBeTruthy();
  });

  it('should set the plural archive SEO title', async () => {
    await settle();
    flushContents([]);

    expect(TestBed.inject(Title).getTitle()).toContain('Articles |');
  });

  it('should render the archive page title', async () => {
    await settle();
    flushContents([]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain("Everything I've written down.");
  });

  it('should render a spine entry for every written content type when loaded', async () => {
    await settle();
    flushContents([
      buildMockContent({ id: '1', title: 'An Article', type: 'article' }),
      buildMockContent({ id: '2', title: 'An Essay', type: 'essay' }),
      buildMockContent({ id: '3', title: 'A Build Log', type: 'build-log' }),
      buildMockContent({ id: '4', title: 'A TIL', type: 'til' }),
      buildMockContent({ id: '5', title: 'A Digest', type: 'digest' }),
    ]);
    await settle();
    await renderList();

    const el = fixture.nativeElement as HTMLElement;
    const rows = el.querySelectorAll('.ed-entry');
    expect(rows.length).toBe(5);
    expect(el.textContent).toContain('An Essay');
    expect(el.textContent).toContain('A Build Log');
  });

  it('should group rows by published year, newest year first', async () => {
    await settle();
    flushContents([
      buildMockContent({
        id: '1',
        title: 'newer',
        published_at: '2026-06-01T00:00:00Z',
      }),
      buildMockContent({
        id: '2',
        title: 'older',
        published_at: '2025-03-01T00:00:00Z',
      }),
    ]);
    await settle();
    await renderList();

    const heads = Array.from(
      (fixture.nativeElement as HTMLElement).querySelectorAll(
        '[data-testid="year-head"]',
      ),
    ).map((h) => h.textContent?.replace(/\s+/g, ' ').trim());
    expect(heads.length).toBe(2);
    expect(heads[0]).toContain('2026'); // newest year first
    expect(heads[1]).toContain('2025');
  });

  it('should link every row to the single reading surface at /articles/:slug', async () => {
    await settle();
    flushContents([buildMockContent({ id: '1', slug: 'my-til', type: 'til' })]);
    await settle();
    await renderList();

    const row = (fixture.nativeElement as HTMLElement).querySelector(
      '.ed-entry',
    );
    expect(row?.getAttribute('href')).toBe('/articles/my-til');
  });

  it('should pass the type query param to the contents request', async () => {
    fixture.componentRef.setInput('type', 'til');
    await settle();

    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/contents') && r.method === 'GET',
    );
    expect(req.request.params.get('type')).toBe('til');
    req.flush({ data: [], meta: buildMockMeta({ total: 0 }) });
  });

  it('should ignore an unknown type query param', async () => {
    fixture.componentRef.setInput('type', 'bogus');
    await settle();

    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/contents') && r.method === 'GET',
    );
    expect(req.request.params.has('type')).toBe(false);
    req.flush({ data: [], meta: buildMockMeta({ total: 0 }) });
  });

  it('should show the empty state when no contents are returned', async () => {
    await settle();
    flushContents([]);
    await settle();
    await renderList();

    const el = fixture.nativeElement as HTMLElement;
    expect(
      el.querySelector('[data-testid="articles-empty"]'),
    ).not.toBeNull();
    expect(el.textContent).toContain('Nothing here yet');
  });

  it('should show an error state when the request fails', async () => {
    await settle();

    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/contents') && r.method === 'GET',
    );
    req.flush('Server error', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    await settle();
    await renderList();

    const el = fixture.nativeElement as HTMLElement;
    // A failed index surfaces a distinct error state — not the empty state.
    expect(el.querySelector('[data-testid="articles-error"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="articles-retry"]')).not.toBeNull();
    expect(el.textContent).toContain("Couldn't load the index");
    expect(el.textContent).not.toContain('Nothing here yet');
  });

  it('should hide pagination when there is only one page', async () => {
    await settle();
    flushContents([buildMockContent()], buildMockMeta({ total_pages: 1 }));
    await settle();
    await renderList();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('nav[aria-label="Pagination"]')).toBeNull();
  });

  it('should show pagination when there are multiple pages', async () => {
    await settle();
    flushContents(
      [buildMockContent()],
      buildMockMeta({ total: 120, total_pages: 3 }),
    );
    await settle();
    await renderList();

    const el = fixture.nativeElement as HTMLElement;
    const pager = el.querySelector('nav[aria-label="Pagination"]');
    expect(pager).not.toBeNull();
    expect(pager?.textContent).toContain('1 / 3');
  });
});
