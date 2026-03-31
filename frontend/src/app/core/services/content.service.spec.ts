import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { ContentService } from './content.service';
import type { ApiContent, ApiPaginationMeta, ApiListResponse } from '../models';

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
    is_public: true,
    ai_metadata: null,
    reading_time_min: 5,
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
    per_page: 10,
    total_pages: 1,
    ...overrides,
  };
}

describe('ContentService', () => {
  let service: ContentService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ContentService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('listPublished', () => {
    it('should fetch published content list', () => {
      const mockContent = createMockContent();
      const mockMeta = createMockMeta();

      service.listPublished().subscribe((response) => {
        expect(response.data).toEqual([mockContent]);
        expect(response.meta).toEqual(mockMeta);
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents'));
      expect(req.request.method).toBe('GET');
      req.flush({ data: [mockContent], meta: mockMeta } as ApiListResponse<ApiContent>);
    });

    it('should pass type filter parameter', () => {
      service.listPublished({ type: 'til' }).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents') && r.params.get('type') === 'til',
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [], meta: createMockMeta() });
    });

    it('should pass tag filter parameter', () => {
      service.listPublished({ tag: 'Go' }).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents') && r.params.get('tag') === 'Go',
      );
      req.flush({ data: [], meta: createMockMeta() });
    });

    it('should pass page and perPage parameters', () => {
      service.listPublished({ page: 3, perPage: 20 }).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents') &&
        r.params.get('page') === '3' &&
        r.params.get('per_page') === '20',
      );
      req.flush({ data: [], meta: createMockMeta({ page: 3, per_page: 20 }) });
    });
  });

  describe('getBySlug', () => {
    it('should fetch single content by slug', () => {
      const mockContent = createMockContent({ slug: 'my-article' });

      service.getBySlug('my-article').subscribe((content) => {
        expect(content).toEqual(mockContent);
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/my-article'));
      expect(req.request.method).toBe('GET');
      req.flush({ data: mockContent });
    });

    it('should propagate 404 error', () => {
      service.getBySlug('not-found').subscribe({
        error: (err: { status: number }) => {
          expect(err.status).toBe(404);
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/not-found'));
      req.flush('Not Found', { status: 404, statusText: 'Not Found' });
    });
  });

  describe('listByType', () => {
    it('should fetch content list by type', () => {
      const mockContent = createMockContent({ type: 'til' });

      service.listByType('til').subscribe((response) => {
        expect(response.data).toEqual([mockContent]);
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/by-type/til'));
      expect(req.request.method).toBe('GET');
      req.flush({ data: [mockContent], meta: createMockMeta() });
    });

    it('should pass pagination params for listByType', () => {
      service.listByType('bookmark', { page: 2, perPage: 5 }).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/by-type/bookmark') &&
        r.params.get('page') === '2' &&
        r.params.get('per_page') === '5',
      );
      req.flush({ data: [], meta: createMockMeta({ page: 2, per_page: 5 }) });
    });
  });

  describe('search', () => {
    it('should search content with query string', () => {
      service.search('angular signals').subscribe((response) => {
        expect(response.data).toHaveLength(0);
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/search') && r.params.get('q') === 'angular signals',
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [], meta: createMockMeta() });
    });

    it('should pass pagination params for search', () => {
      service.search('go', { page: 2, perPage: 10 }).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/search') &&
        r.params.get('q') === 'go' &&
        r.params.get('page') === '2',
      );
      req.flush({ data: [], meta: createMockMeta() });
    });
  });

  describe('create', () => {
    it('should POST to admin contents endpoint', () => {
      const request = {
        slug: 'new-til',
        title: 'New TIL',
        type: 'til' as const,
      };
      const mockResponse = createMockContent({ slug: 'new-til', title: 'New TIL', type: 'til' });

      service.create(request).subscribe((content) => {
        expect(content.title).toBe('New TIL');
        expect(content.type).toBe('til');
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/admin/contents'));
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual(request);
      req.flush({ data: mockResponse });
    });
  });

  describe('update', () => {
    it('should PUT to admin contents endpoint with id', () => {
      const mockResponse = createMockContent({ title: 'Updated Title' });

      service.update('content-001', { title: 'Updated Title' }).subscribe((content) => {
        expect(content.title).toBe('Updated Title');
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/admin/contents/content-001'),
      );
      expect(req.request.method).toBe('PUT');
      req.flush({ data: mockResponse });
    });
  });

  describe('remove', () => {
    it('should DELETE admin contents endpoint with id', () => {
      service.remove('content-001').subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/admin/contents/content-001'),
      );
      expect(req.request.method).toBe('DELETE');
      req.flush(null);
    });
  });

  describe('publish', () => {
    it('should POST to publish endpoint', () => {
      const mockResponse = createMockContent({ status: 'published' });

      service.publish('content-001').subscribe((content) => {
        expect(content.status).toBe('published');
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/admin/contents/content-001/publish'),
      );
      expect(req.request.method).toBe('POST');
      req.flush({ data: mockResponse });
    });
  });
});
