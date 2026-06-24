import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  provideHttpClientTesting,
  HttpTestingController,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { HomeComponent } from './home';
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
    description: 'Working through the language',
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
    id: 'c-1',
    slug: 'a-piece',
    title: 'A Piece',
    excerpt: 'An excerpt',
    body: '',
    type: 'article',
    status: 'published',
    topics: [{ id: 'topic-1', slug: 'go', name: 'Go' }],
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
  return { total: 1, page: 1, per_page: 50, total_pages: 1, ...overrides };
}

describe('HomeComponent', () => {
  let component: HomeComponent;
  let fixture: ComponentFixture<HomeComponent>;
  let httpTesting: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HomeComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpTesting = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(HomeComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpTesting.verify();
  });

  /** Flush effects + microtasks so each rxResource issues its request. */
  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
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

  function flushTopics(topics: ApiTopic[]): void {
    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/topics') && r.method === 'GET',
    );
    req.flush({ data: topics });
  }

  it('should render the owner-set positioning statement', async () => {
    await settle();
    flushContents([]);
    flushTopics([]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain("Notes, systems, and what I'm working out.");
  });

  it('should render a theme row only for topics with published pieces', async () => {
    await settle();
    flushContents([buildMockContent()]);
    flushTopics([
      buildMockTopic({ id: 't1', slug: 'go', name: 'Go', content_count: 1 }),
      buildMockTopic({
        id: 't2',
        slug: 'empty',
        name: 'Empty',
        content_count: 0,
      }),
    ]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    const rows = Array.from(
      el.querySelectorAll('[data-testid="theme-row"]'),
    ).map((r) => r.textContent ?? '');
    expect(rows.length).toBe(1);
    expect(rows[0]).toContain('Go');
  });

  it('should fold zero-piece topics into one "Also following" line', async () => {
    await settle();
    flushContents([buildMockContent()]);
    flushTopics([
      buildMockTopic({ id: 't1', slug: 'go', name: 'Go', content_count: 1 }),
      buildMockTopic({
        id: 't2',
        slug: 'rust',
        name: 'Rust',
        content_count: 0,
      }),
    ]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    const following = el.querySelector('[data-testid="following"]');
    expect(following?.textContent).toContain('Also following');
    expect(following?.textContent).toContain('Rust');
  });

  it('should show the latest piece inline only when a topic has 2+ pieces', async () => {
    await settle();
    flushContents([
      buildMockContent({
        id: 'c1',
        slug: 'newest',
        title: 'Newest Go piece',
        type: 'til',
      }),
    ]);
    flushTopics([
      buildMockTopic({ id: 't1', slug: 'go', name: 'Go', content_count: 3 }),
    ]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    const row = el.querySelector('[data-testid="theme-row"]');
    expect(row?.textContent).toContain('Newest Go piece');
  });

  it('should list the three most recent pieces and a read-everything link', async () => {
    await settle();
    flushContents([
      buildMockContent({ id: '1', slug: 'a', title: 'First' }),
      buildMockContent({ id: '2', slug: 'b', title: 'Second' }),
      buildMockContent({ id: '3', slug: 'c', title: 'Third' }),
      buildMockContent({ id: '4', slug: 'd', title: 'Fourth' }),
    ]);
    flushTopics([buildMockTopic({ content_count: 4 })]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    const recent = el.querySelectorAll('[data-testid="recent-row"]');
    expect(recent.length).toBe(3);
    expect(el.textContent).toContain('First');
    expect(el.textContent).not.toContain('Fourth');
    expect(
      el.querySelector('[data-testid="read-everything"]')?.getAttribute('href'),
    ).toBe('/articles');
  });

  it('should stay standing when the content request fails (500)', async () => {
    await settle();

    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/contents') && r.method === 'GET',
    );
    req.flush('Server error', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    flushTopics([buildMockTopic({ content_count: 0 })]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    // The positioning band is static — the page renders even with no feed.
    expect(el.textContent).toContain("Notes, systems, and what I'm working out.");
    expect(component['recent']().length).toBe(0);
  });

  it('should render the error UI with retry when the feed fails (500)', async () => {
    await settle();

    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/contents') && r.method === 'GET',
    );
    req.flush('Server error', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    flushTopics([buildMockTopic({ content_count: 0 })]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(component['hasError']()).toBe(true);
    expect(el.querySelector('[data-testid="home-error"]')).toBeTruthy();
    expect(el.querySelector('[data-testid="home-error-retry"]')).toBeTruthy();
    // The false "Nothing published yet" empty state must NOT render on error.
    expect(el.querySelector('[data-testid="recent-empty"]')).toBeNull();
  });
});
