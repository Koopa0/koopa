import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TagService } from './tag.service';
import type { ApiContent, ApiPaginationMeta } from '../models';

function createMockContent(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'content-001',
    slug: 'test-content',
    title: 'Test Content',
    body: '# Test',
    excerpt: 'A test content',
    type: 'article',
    status: 'published',
    tags: ['Angular'],
    topics: [],
    cover_image: null,
    source: null,
    source_type: null,
    series_id: null,
    series_order: null,
    review_level: 'auto',
    ai_metadata: null,
    reading_time: 5,
    published_at: '2026-01-15T10:00:00Z',
    created_at: '2026-01-10T10:00:00Z',
    updated_at: '2026-01-15T10:00:00Z',
    ...overrides,
  };
}

function createMockMeta(overrides: Partial<ApiPaginationMeta> = {}): ApiPaginationMeta {
  return {
    total: 1,
    page: 1,
    per_page: 20,
    total_pages: 1,
    ...overrides,
  };
}

describe('TagService', () => {
  let service: TagService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(TagService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should have loading signal initialized to false', () => {
    expect(service.loading()).toBe(false);
  });

  it('should have errorMessage signal initialized to null', () => {
    expect(service.errorMessage()).toBeNull();
  });

  describe('getContentsByTag', () => {
    it('should fetch contents by tag and map response correctly', () => {
      const mockContent = createMockContent({ tags: ['Angular'] });
      const mockMeta = createMockMeta();

      service.getContentsByTag('Angular').subscribe((response) => {
        expect(response.contents).toEqual([mockContent]);
        expect(response.meta).toEqual(mockMeta);
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents') && r.params.get('tag') === 'Angular',
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [mockContent], meta: mockMeta });
    });

    it('should set loading to true when called and false after response', () => {
      service.getContentsByTag('Go').subscribe();
      expect(service.loading()).toBe(true);

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents') && r.params.get('tag') === 'Go',
      );
      req.flush({ data: [], meta: createMockMeta() });

      expect(service.loading()).toBe(false);
    });

    it('should pass page and perPage parameters', () => {
      service.getContentsByTag('TypeScript', 2, 10).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents') &&
        r.params.get('tag') === 'TypeScript' &&
        r.params.get('page') === '2' &&
        r.params.get('per_page') === '10',
      );
      req.flush({ data: [], meta: createMockMeta({ page: 2, per_page: 10 }) });
    });

    it('should set error message on failure', () => {
      service.getContentsByTag('Angular').subscribe({
        error: () => {
          // expected
        },
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents') && r.params.get('tag') === 'Angular',
      );
      req.flush('Server error', { status: 500, statusText: 'Internal Server Error' });

      expect(service.loading()).toBe(false);
      expect(service.errorMessage()).toBe('Failed to load tag content');
    });

    it('should clear previous error on new request', () => {
      // First request fails
      service.getContentsByTag('Angular').subscribe({ error: () => { /* expected error */ } });
      const req1 = httpMock.expectOne((r) => r.url.includes('/api/contents'));
      req1.flush('Error', { status: 500, statusText: 'Error' });
      expect(service.errorMessage()).toBe('Failed to load tag content');

      // Second request clears error
      service.getContentsByTag('Go').subscribe();
      expect(service.errorMessage()).toBeNull();

      const req2 = httpMock.expectOne((r) => r.url.includes('/api/contents'));
      req2.flush({ data: [], meta: createMockMeta() });
    });
  });
});
