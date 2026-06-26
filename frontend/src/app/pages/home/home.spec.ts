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
  return { total: 1, page: 1, per_page: 5, total_pages: 1, ...overrides };
}

function buildMockTopic(overrides: Partial<ApiTopic> = {}): ApiTopic {
  return {
    id: 't-1',
    slug: 'go',
    name: 'Go & systems',
    description: '',
    icon: '',
    content_count: 4,
    sort_order: 1,
    created_at: '2026-01-15T00:00:00Z',
    updated_at: '2026-01-15T00:00:00Z',
    ...overrides,
  };
}

describe('HomeComponent', () => {
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
  });

  afterEach(() => {
    httpTesting.verify();
  });

  /** Flush effects + macrotasks so the rxResources issue their requests. */
  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function flushContents(
    contents: ApiContent[],
    meta: ApiPaginationMeta = buildMockMeta({ total: contents.length }),
  ): void {
    httpTesting
      .expectOne((r) => r.url.includes('/api/contents') && r.method === 'GET')
      .flush({ data: contents, meta });
  }

  function flushTopics(topics: ApiTopic[] = []): void {
    httpTesting
      .expectOne((r) => r.url.includes('/api/topics') && r.method === 'GET')
      .flush({ data: topics });
  }

  it('should render the positioning statement as the single h1', async () => {
    await settle();
    flushContents([]);
    flushTopics();
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelectorAll('h1').length).toBe(1);
    expect(el.querySelector('h1')?.textContent).toContain(
      "Notes, systems, and what I'm working out.",
    );
  });

  it('should feature the newest piece as the lead', async () => {
    await settle();
    flushContents([
      buildMockContent({ id: '1', slug: 'lead-piece', title: 'The Lead' }),
      buildMockContent({ id: '2', slug: 'b', title: 'Second' }),
    ]);
    flushTopics();
    await settle();

    const lead = (fixture.nativeElement as HTMLElement).querySelector(
      '[data-testid="home-lead"]',
    );
    expect(lead?.textContent).toContain('The Lead');
    expect(lead?.getAttribute('href')).toBe('/articles/lead-piece');
  });

  it('should list the remaining recent pieces under the lead', async () => {
    await settle();
    flushContents([
      buildMockContent({ id: '1', slug: 'a', title: 'Lead' }),
      buildMockContent({ id: '2', slug: 'b', title: 'Second' }),
      buildMockContent({ id: '3', slug: 'c', title: 'Third' }),
    ]);
    flushTopics();
    await settle();

    const rows = (fixture.nativeElement as HTMLElement).querySelectorAll(
      '[data-testid="home-rec"]',
    );
    expect(rows.length).toBe(2); // 3 contents − 1 lead
  });

  it('should point the read-everything link at the article wall', async () => {
    await settle();
    flushContents([]);
    flushTopics();
    await settle();

    expect(
      (fixture.nativeElement as HTMLElement)
        .querySelector('[data-testid="read-everything"]')
        ?.getAttribute('href'),
    ).toBe('/articles');
  });

  it('should show an empty line when nothing is published', async () => {
    await settle();
    flushContents([], buildMockMeta({ total: 0 }));
    flushTopics();
    await settle();

    expect(
      (fixture.nativeElement as HTMLElement).querySelector(
        '[data-testid="recent-empty"]',
      )?.textContent,
    ).toContain('Nothing published yet.');
  });

  it('should hide the topic index while the corpus is below the cold-start floor', async () => {
    await settle();
    // 3 published pieces — below the MIN_PIECES floor — so the counts would lie.
    flushContents(
      [
        buildMockContent({ id: '1', slug: 'a' }),
        buildMockContent({ id: '2', slug: 'b' }),
        buildMockContent({ id: '3', slug: 'c' }),
      ],
      buildMockMeta({ total: 3 }),
    );
    flushTopics([
      buildMockTopic({ id: 't1', slug: 'go', name: 'Go' }),
      buildMockTopic({ id: 't2', slug: 'pg', name: 'Postgres' }),
      buildMockTopic({ id: 't3', slug: 'ai', name: 'AI' }),
    ]);
    await settle();

    expect(
      (fixture.nativeElement as HTMLElement).querySelector(
        '[data-testid="home-topic"]',
      ),
    ).toBeNull();
  });

  it('should reveal the topic index once the corpus clears the floor', async () => {
    await settle();
    flushContents(
      Array.from({ length: 5 }, (_, i) =>
        buildMockContent({ id: `${i}`, slug: `p-${i}` }),
      ),
      buildMockMeta({ total: 8 }),
    );
    flushTopics([
      buildMockTopic({ id: 't1', slug: 'go', name: 'Go', content_count: 7 }),
      buildMockTopic({ id: 't2', slug: 'pg', name: 'Postgres', content_count: 5 }),
      buildMockTopic({ id: 't3', slug: 'ai', name: 'AI', content_count: 3 }),
      buildMockTopic({ id: 't0', slug: 'empty', name: 'Empty', content_count: 0 }),
    ]);
    await settle();

    const topics = (fixture.nativeElement as HTMLElement).querySelectorAll(
      '[data-testid="home-topic"]',
    );
    // 3 non-empty topics shown; the count-0 topic is suppressed.
    expect(topics.length).toBe(3);
    expect(topics[0].textContent).toContain('Go');
  });

  it('should stay standing when the content request fails (500)', async () => {
    await settle();

    httpTesting
      .expectOne((r) => r.url.includes('/api/contents') && r.method === 'GET')
      .flush('err', { status: 500, statusText: 'Internal Server Error' });
    flushTopics();
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain(
      "Notes, systems, and what I'm working out.",
    );
    expect(el.querySelectorAll('h1').length).toBe(1);
    expect(el.querySelector('[data-testid="home-lead"]')).toBeNull();
  });
});
