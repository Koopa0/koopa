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
import { ArticlesComponent } from './articles';
import type {
  ApiContent,
  ApiPaginationMeta,
  ApiTopic,
} from '../../core/models';

function buildMockTopic(overrides: Partial<ApiTopic> = {}): ApiTopic {
  return {
    id: 'topic-1',
    slug: 'go',
    name: 'Go',
    description: 'Go programming',
    icon: '',
    content_count: 1,
    sort_order: 1,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

function buildMockContent(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'test-1',
    slug: 'test-article',
    title: 'Test Article',
    excerpt: 'A test excerpt',
    body: '',
    type: 'article',
    status: 'published',
    topics: [buildMockTopic()],
    cover_image: null,
    series_id: null,
    series_order: null,
    is_public: true,
    ai_metadata: null,
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

  function flushTopics(topics: ApiTopic[] = [buildMockTopic()]): void {
    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/topics') && r.method === 'GET',
    );
    req.flush({ data: topics });
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
    flushTopics();
    expect(component).toBeTruthy();
  });

  it('should render rows for every written content type when loaded', async () => {
    await settle();
    flushContents([
      buildMockContent({ id: '1', title: 'An Article', type: 'article' }),
      buildMockContent({ id: '2', title: 'An Essay', type: 'essay' }),
      buildMockContent({ id: '3', title: 'A Build Log', type: 'build-log' }),
      buildMockContent({ id: '4', title: 'A TIL', type: 'til' }),
      buildMockContent({ id: '5', title: 'A Digest', type: 'digest' }),
    ]);
    flushTopics();
    await settle();
    await renderList();

    const el = fixture.nativeElement as HTMLElement;
    const rows = el.querySelectorAll('[data-testid="index-row"]');
    expect(rows.length).toBe(5);
    expect(el.textContent).toContain('An Essay');
    expect(el.textContent).toContain('A Build Log');
  });

  it('should only render topic chips for topics with published content', async () => {
    await settle();
    flushContents([buildMockContent()]);
    flushTopics([
      buildMockTopic({ id: 't1', slug: 'go', name: 'Go', content_count: 2 }),
      buildMockTopic({ id: 't2', slug: 'empty', name: 'Empty', content_count: 0 }),
    ]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    const labels = Array.from(
      el.querySelectorAll('[data-testid="topic-chip"]'),
    ).map((c) => c.textContent?.trim());
    expect(labels).toContain('Go');
    expect(labels).not.toContain('Empty');
  });

  it('should link every row to the single reading surface at /articles/:slug', async () => {
    await settle();
    flushContents([
      buildMockContent({ id: '1', slug: 'my-til', type: 'til' }),
    ]);
    flushTopics();
    await settle();

    await renderList();

    const row = (fixture.nativeElement as HTMLElement).querySelector(
      '[data-testid="index-row"]',
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
    flushTopics();
  });

  it('should ignore an unknown type query param', async () => {
    fixture.componentRef.setInput('type', 'bogus');
    await settle();

    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/contents') && r.method === 'GET',
    );
    expect(req.request.params.has('type')).toBe(false);
    req.flush({ data: [], meta: buildMockMeta({ total: 0 }) });
    flushTopics();
  });

  it('should filter rows client-side when a topic chip is selected', async () => {
    await settle();
    flushContents([
      buildMockContent({
        id: '1',
        title: 'Go piece',
        topics: [buildMockTopic({ slug: 'go', name: 'Go' })],
      }),
      buildMockContent({
        id: '2',
        title: 'Angular piece',
        topics: [buildMockTopic({ id: 't2', slug: 'angular', name: 'Angular' })],
      }),
    ]);
    flushTopics([
      buildMockTopic({ slug: 'go', name: 'Go' }),
      buildMockTopic({ id: 't2', slug: 'angular', name: 'Angular' }),
    ]);
    await settle();

    component['selectTopic']('go');
    await settle();
    await renderList();

    const el = fixture.nativeElement as HTMLElement;
    const rows = el.querySelectorAll('[data-testid="index-row"]');
    expect(rows.length).toBe(1);
    expect(el.textContent).toContain('Go piece');
    expect(el.textContent).not.toContain('Angular piece');
  });

  it('should show the empty state when no contents are returned', async () => {
    await settle();
    flushContents([]);
    flushTopics();
    await settle();
    await renderList();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Nothing here yet');
  });

  it('should fall back to the empty state when the request fails', async () => {
    await settle();

    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/contents') && r.method === 'GET',
    );
    req.flush('Server error', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    flushTopics();
    await settle();

    await renderList();

    const el = fixture.nativeElement as HTMLElement;
    // A failed index degrades to the empty state — no scary error UI.
    expect(el.textContent).toContain('Nothing here yet');
    expect(el.textContent).not.toContain('Could not load the index');
  });

  it('should render the hero lead and topic chips', async () => {
    await settle();
    flushContents([]);
    flushTopics([buildMockTopic({ slug: 'go', name: 'Go' })]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain("Everything I've written down.");
    expect(
      el.querySelector('[data-testid="topic-chip-all"]'),
    ).toBeTruthy();
    expect(el.querySelectorAll('[data-testid="topic-chip"]').length).toBe(1);
  });
});
