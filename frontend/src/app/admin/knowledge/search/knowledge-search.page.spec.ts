import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';

import { KnowledgeSearchPageComponent } from './knowledge-search.page';

const SEARCH_URL = '/api/admin/search';

describe('KnowledgeSearchPageComponent', () => {
  let fixture: ComponentFixture<KnowledgeSearchPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(KnowledgeSearchPageComponent);
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  /** Waits out the input debounce, then settles change detection. */
  async function settleDebounce(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 300));
    fixture.detectChanges();
  }

  /** Lets a flushed response propagate into the resource, then renders. */
  async function settle(): Promise<void> {
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function type(value: string): void {
    const input = el().querySelector<HTMLInputElement>(
      '[data-testid="knowledge-search-input"]',
    );
    input!.value = value;
    input!.dispatchEvent(new Event('input'));
  }

  function flushResults(
    results: Record<string, unknown>[],
    expectedQ?: string,
  ): void {
    const req = httpMock.expectOne((r) => r.url.endsWith(SEARCH_URL));
    if (expectedQ !== undefined) {
      expect(req.request.params.get('q')).toBe(expectedQ);
    }
    req.flush({ data: { results } });
  }

  it('should show the idle state and make no request before a query is typed', () => {
    expect(
      el().querySelector('[data-testid="knowledge-search-idle"]'),
    ).toBeTruthy();
    httpMock.expectNone((r) => r.url.endsWith(SEARCH_URL));
  });

  it('should query the admin search endpoint and render dense rows after the debounce', async () => {
    type('pgvector');
    await settleDebounce();

    flushResults(
      [
        {
          type: 'content',
          id: 'c1',
          slug: 'pgvector-indexing',
          title: 'pgvector indexing',
          excerpt: 'HNSW vs IVFFlat',
          score: 0.9,
        },
        { type: 'note', id: 'n1', title: 'pgvector capture', score: 0 },
      ],
      'pgvector',
    );
    await settle();

    const rows = el().querySelectorAll('[data-testid^="knowledge-search-row-"]');
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain('content');
    expect(rows[0].textContent).toContain('pgvector indexing');
    expect(rows[0].textContent).toContain('HNSW vs IVFFlat');
    expect(rows[1].textContent).toContain('note');
    expect(
      el().querySelector('[data-testid="knowledge-search-count"]')?.textContent,
    ).toContain('2 results');
  });

  it('should navigate to the matching editor route when a row is clicked', async () => {
    const navigate = vi
      .spyOn(TestBed.inject(Router), 'navigate')
      .mockResolvedValue(true);

    type('go');
    await settleDebounce();
    flushResults([
      { type: 'content', id: 'c1', title: 'Go values', score: 0 },
      { type: 'note', id: 'n1', title: 'Go note', score: 0 },
    ]);
    await settle();

    el()
      .querySelector<HTMLButtonElement>(
        '[data-testid="knowledge-search-row-0"]',
      )
      ?.click();
    expect(navigate).toHaveBeenCalledWith([
      '/admin/knowledge/content',
      'c1',
      'edit',
    ]);

    el()
      .querySelector<HTMLButtonElement>(
        '[data-testid="knowledge-search-row-1"]',
      )
      ?.click();
    expect(navigate).toHaveBeenCalledWith([
      '/admin/knowledge/notes',
      'n1',
      'edit',
    ]);
  });

  it('should show the empty state when the query matches nothing', async () => {
    type('zzz');
    await settleDebounce();
    flushResults([]);
    await settle();

    expect(
      el().querySelector('[data-testid="knowledge-search-empty"]'),
    ).toBeTruthy();
  });

  it('should show the error state when the endpoint fails', async () => {
    type('boom');
    await settleDebounce();
    httpMock
      .expectOne((r) => r.url.endsWith(SEARCH_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'search failed' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    await settle();

    expect(
      el().querySelector('[data-testid="knowledge-search-error"]'),
    ).toBeTruthy();
  });
});
