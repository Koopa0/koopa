import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { SearchService } from './search.service';
import type { ApiListResponse, ApiContent } from '../models';

function makeMockContent(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: '1',
    slug: 'test-article',
    title: 'Test Article',
    body: 'Test body content',
    excerpt: 'Test excerpt',
    type: 'article',
    status: 'published',
    tags: ['test'],
    topics: [],
    cover_image: null,
    source: null,
    source_type: null,
    series_id: null,
    series_order: null,
    review_level: 'standard',
    visibility: 'public',
    ai_metadata: null,
    reading_time: 5,
    published_at: '2026-01-01T00:00:00Z',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('SearchService', () => {
  let service: SearchService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(SearchService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should start with empty state', () => {
    expect(service.query()).toBe('');
    expect(service.results()).toEqual([]);
    expect(service.searching()).toBe(false);
    expect(service.hasResults()).toBe(false);
  });

  it('should search and populate results from backend', () => {
    const mockResponse: ApiListResponse<ApiContent> = {
      data: [makeMockContent({ id: '1', title: 'Angular Signals' })],
      meta: { total: 1, page: 1, per_page: 20, total_pages: 1 },
    };

    service.search('Angular');

    expect(service.searching()).toBe(true);

    const req = httpMock.expectOne((r) => r.url.includes('/api/search'));
    expect(req.request.params.get('q')).toBe('Angular');
    req.flush(mockResponse);

    expect(service.searching()).toBe(false);
    expect(service.hasResults()).toBe(true);
    expect(service.results().length).toBe(1);
    expect(service.meta()?.total).toBe(1);
  });

  it('should set empty results for blank query without HTTP call', () => {
    service.search('');

    httpMock.expectNone((r) => r.url.includes('/api/search'));
    expect(service.hasResults()).toBe(false);
    expect(service.results()).toEqual([]);
  });

  it('should clear search state', () => {
    const mockResponse: ApiListResponse<ApiContent> = {
      data: [makeMockContent()],
      meta: { total: 1, page: 1, per_page: 20, total_pages: 1 },
    };

    service.search('test');
    httpMock.expectOne((r) => r.url.includes('/api/search')).flush(mockResponse);
    expect(service.hasResults()).toBe(true);

    service.clearSearch();
    expect(service.query()).toBe('');
    expect(service.results()).toEqual([]);
    expect(service.meta()).toBeNull();
  });
});
