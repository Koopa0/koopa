import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  provideHttpClientTesting,
  HttpTestingController,
} from '@angular/common/http/testing';
import {
  provideRouter,
  RedirectCommand,
  convertToParamMap,
  ActivatedRouteSnapshot,
  RouterStateSnapshot,
} from '@angular/router';
import { firstValueFrom, type Observable } from 'rxjs';
import { articleResolver } from './article-resolver';
import type { ApiContent } from '../../core/models';

function buildMockContent(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'test-1',
    slug: 'a-piece',
    title: 'A Piece',
    excerpt: 'An excerpt',
    body: 'Body text.',
    type: 'article',
    status: 'published',
    topics: [],
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

describe('articleResolver', () => {
  let httpTesting: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpTesting = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpTesting.verify());

  function run(slug: string): Observable<ApiContent | RedirectCommand> {
    const route = {
      paramMap: convertToParamMap({ slug }),
    } as ActivatedRouteSnapshot;
    const state = {} as RouterStateSnapshot;
    return TestBed.runInInjectionContext(
      () =>
        articleResolver(route, state) as Observable<
          ApiContent | RedirectCommand
        >,
    );
  }

  it('should resolve the article on success', async () => {
    const result = firstValueFrom(run('a-piece'));
    httpTesting
      .expectOne((r) => r.url.includes('/api/contents/a-piece'))
      .flush({ data: buildMockContent() });

    expect(await result).toEqual(buildMockContent());
  });

  it('should redirect a 404 to the not-found page', async () => {
    const result = firstValueFrom(run('missing'));
    httpTesting
      .expectOne((r) => r.url.includes('/api/contents/missing'))
      .flush('nope', { status: 404, statusText: 'Not Found' });

    const resolved = await result;
    expect(resolved).toBeInstanceOf(RedirectCommand);
    expect((resolved as RedirectCommand).redirectTo.toString()).toBe(
      '/not-found',
    );
  });

  it('should redirect a 500 to the error page', async () => {
    const result = firstValueFrom(run('broken'));
    httpTesting
      .expectOne((r) => r.url.includes('/api/contents/broken'))
      .flush('boom', { status: 500, statusText: 'Internal Server Error' });

    const resolved = await result;
    expect(resolved).toBeInstanceOf(RedirectCommand);
    expect((resolved as RedirectCommand).redirectTo.toString()).toBe('/error');
  });
});
