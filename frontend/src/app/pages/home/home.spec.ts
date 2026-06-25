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

  /** Force the deferred recent-list block into its rendered (Complete) state. */
  async function renderDeferredList(): Promise<void> {
    const blocks = await fixture.getDeferBlocks();
    await blocks[0].render(DeferBlockState.Complete);
    fixture.detectChanges();
  }

  it('should render the owner-set positioning statement', async () => {
    await settle();
    flushContents([]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain(
      "Notes, systems, and what I'm working out.",
    );
  });

  it('should point the read-everything link at the article wall', async () => {
    await settle();
    flushContents([]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(
      el.querySelector('[data-testid="read-everything"]')?.getAttribute('href'),
    ).toBe('/articles');
  });

  it('should render the recent pieces as cards once the list hydrates', async () => {
    await settle();
    flushContents([
      buildMockContent({ id: '1', slug: 'a', title: 'First' }),
      buildMockContent({ id: '2', slug: 'b', title: 'Second' }),
      buildMockContent({ id: '3', slug: 'c', title: 'Third' }),
    ]);
    await settle();
    await renderDeferredList();

    const el = fixture.nativeElement as HTMLElement;
    const rows = el.querySelectorAll('[data-testid="index-row"]');
    expect(rows.length).toBe(3);
    expect(el.textContent).toContain('First');
    expect(rows[0].getAttribute('href')).toBe('/articles/a');
  });

  it('should show an empty line when nothing is published', async () => {
    await settle();
    flushContents([]);
    await settle();
    await renderDeferredList();

    const el = fixture.nativeElement as HTMLElement;
    expect(
      el.querySelector('[data-testid="recent-empty"]')?.textContent,
    ).toContain('Nothing published yet.');
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
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    // The intro band is static — the page renders even with no feed.
    expect(el.textContent).toContain(
      "Notes, systems, and what I'm working out.",
    );
    expect(component['recent']().length).toBe(0);
  });
});
