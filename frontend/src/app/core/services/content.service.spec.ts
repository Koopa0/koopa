import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
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
    topics: [],
    cover_image: null,
    series_id: null,
    series_order: null,
    is_public: true,
    reading_time_min: 5,
    published_at: '2026-01-15T10:00:00Z',
    created_at: '2026-01-10T10:00:00Z',
    updated_at: '2026-01-15T10:00:00Z',
    ...overrides,
  };
}

function createMockMeta(
  overrides: Partial<ApiPaginationMeta> = {},
): ApiPaginationMeta {
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
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
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
      req.flush({
        data: [mockContent],
        meta: mockMeta,
      } as ApiListResponse<ApiContent>);
    });

    it('should pass type filter parameter', () => {
      service.listPublished({ type: 'til' }).subscribe();

      const req = httpMock.expectOne(
        (r) =>
          r.url.includes('/api/contents') && r.params.get('type') === 'til',
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [], meta: createMockMeta() });
    });

    it('should pass tag filter parameter', () => {
      service.listPublished({ tag: 'Go' }).subscribe();

      const req = httpMock.expectOne(
        (r) => r.url.includes('/api/contents') && r.params.get('tag') === 'Go',
      );
      req.flush({ data: [], meta: createMockMeta() });
    });

    it('should pass page and perPage parameters', () => {
      service.listPublished({ page: 3, perPage: 20 }).subscribe();

      const req = httpMock.expectOne(
        (r) =>
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

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/my-article'),
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: mockContent });
    });

    it('should propagate 404 error', () => {
      service.getBySlug('not-found').subscribe({
        error: (err: { status: number }) => {
          expect(err.status).toBe(404);
        },
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/not-found'),
      );
      req.flush('Not Found', { status: 404, statusText: 'Not Found' });
    });
  });

  describe('listByType', () => {
    it('should fetch content list by type', () => {
      const mockContent = createMockContent({ type: 'til' });

      service.listByType('til').subscribe((response) => {
        expect(response.data).toEqual([mockContent]);
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/by-type/til'),
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [mockContent], meta: createMockMeta() });
    });

    it('should pass pagination params for listByType', () => {
      service.listByType('digest', { page: 2, perPage: 5 }).subscribe();

      const req = httpMock.expectOne(
        (r) =>
          r.url.includes('/api/contents/by-type/digest') &&
          r.params.get('page') === '2' &&
          r.params.get('per_page') === '5',
      );
      req.flush({ data: [], meta: createMockMeta({ page: 2, per_page: 5 }) });
    });
  });

  describe('update', () => {
    it('should PUT to admin contents endpoint with id', () => {
      const mockResponse = createMockContent({ title: 'Updated Title' });

      service
        .update('content-001', { title: 'Updated Title' })
        .subscribe((content) => {
          expect(content.title).toBe('Updated Title');
        });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/admin/knowledge/content/content-001'),
      );
      expect(req.request.method).toBe('PUT');
      req.flush({ data: mockResponse });
    });
  });

  describe('remove', () => {
    it('should DELETE admin contents endpoint with id', () => {
      service.remove('content-001').subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/admin/knowledge/content/content-001'),
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
        r.url.includes('/api/admin/knowledge/content/content-001/publish'),
      );
      expect(req.request.method).toBe('POST');
      req.flush({ data: mockResponse });
    });
  });

  describe('withdrawal', () => {
    interface WithdrawalService {
      withdraw: (
        id: string,
        reason: string,
      ) => ReturnType<ContentService['publish']>;
      restore: (id: string) => ReturnType<ContentService['publish']>;
    }

    it('should POST the exact owner reason to the withdraw endpoint', () => {
      const withdrawal = service as unknown as WithdrawalService;
      withdrawal
        .withdraw('content-001', 'The source is no longer accurate.')
        .subscribe();

      const req = httpMock.expectOne(
        '/api/admin/knowledge/content/content-001/withdraw',
      );
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({
        reason: 'The source is no longer accurate.',
      });
      req.flush({
        data: createMockContent({ status: 'published', is_public: false }),
      });
    });

    it('should POST an empty body to the restore endpoint', () => {
      const withdrawal = service as unknown as WithdrawalService;
      withdrawal.restore('content-001').subscribe();

      const req = httpMock.expectOne(
        '/api/admin/knowledge/content/content-001/restore',
      );
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({});
      req.flush({ data: createMockContent() });
    });

    it('should not retain the generic visibility mutation surface', () => {
      expect(
        (service as unknown as Record<string, unknown>)['setVisibility'],
      ).toBeUndefined();
    });
  });
});
