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
import type { ApiContent, ApiPaginationMeta } from '../../core/models';

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

  /** Flush effects + macrotasks so the rxResource issues its request. */
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

  it('should render the positioning statement as the single h1', async () => {
    await settle();
    flushContents([]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    // The statement is the always-present <h1> — present even with no lead.
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
    await settle();

    const rows = (fixture.nativeElement as HTMLElement).querySelectorAll(
      '[data-testid="home-rec"]',
    );
    expect(rows.length).toBe(2); // 3 contents − 1 lead
  });

  it('should point the read-everything link at the article wall', async () => {
    await settle();
    flushContents([]);
    await settle();

    expect(
      (fixture.nativeElement as HTMLElement)
        .querySelector('[data-testid="read-everything"]')
        ?.getAttribute('href'),
    ).toBe('/articles');
  });

  it('should show an empty line when nothing is published', async () => {
    await settle();
    flushContents([]);
    await settle();

    expect(
      (fixture.nativeElement as HTMLElement).querySelector(
        '[data-testid="recent-empty"]',
      )?.textContent,
    ).toContain('Nothing published yet.');
  });

  it('should stay standing when the content request fails (500)', async () => {
    await settle();

    httpTesting
      .expectOne((r) => r.url.includes('/api/contents') && r.method === 'GET')
      .flush('err', { status: 500, statusText: 'Internal Server Error' });
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain(
      "Notes, systems, and what I'm working out.",
    );
    // Still exactly one <h1> (the statement) even with no lead on a 500.
    expect(el.querySelectorAll('h1').length).toBe(1);
    expect(el.querySelector('[data-testid="home-lead"]')).toBeNull();
  });
});
