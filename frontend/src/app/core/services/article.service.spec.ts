import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { ArticleService } from './article.service';
import type { ApiContent, ApiListResponse, ApiPaginationMeta } from '../models';

function createMockContent(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'content-001',
    slug: 'test-article',
    title: 'Test Article',
    body: '# Test',
    excerpt: 'A test article',
    type: 'article',
    status: 'published',
    tags: ['Angular'],
    topics: [],
    cover_image: null,
    source: null,
    source_type: null,
    series_id: null,
    series_order: null,
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

describe('ArticleService', () => {
  let service: ArticleService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ArticleService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('getArticles', () => {
    it('should fetch articles and map response correctly', () => {
      const mockArticle = createMockContent();
      const mockMeta = createMockMeta();

      service.getArticles().subscribe((response) => {
        expect(response.articles).toEqual([mockArticle]);
        expect(response.meta).toEqual(mockMeta);
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents') && r.params.get('type') === 'article',
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [mockArticle], meta: mockMeta } as ApiListResponse<ApiContent>);
    });

    it('should pass tag filter parameter', () => {
      service.getArticles({ tag: 'Angular' }).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents') && r.params.get('tag') === 'Angular',
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [], meta: createMockMeta() });
    });

    it('should pass page and perPage parameters', () => {
      service.getArticles({ page: 2, perPage: 5 }).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents') &&
        r.params.get('page') === '2' &&
        r.params.get('per_page') === '5',
      );
      req.flush({ data: [], meta: createMockMeta({ page: 2, per_page: 5 }) });
    });

    it('should use search endpoint when search filter is provided', () => {
      service.getArticles({ search: 'angular signals' }).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/search') && r.params.get('q') === 'angular signals',
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [], meta: createMockMeta() });
    });

    it('should propagate error to subscriber', () => {
      service.getArticles().subscribe({
        error: (err) => {
          expect(err).toBeTruthy();
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents'));
      req.flush('Server error', { status: 500, statusText: 'Internal Server Error' });
    });
  });

  describe('getArticleBySlug', () => {
    it('should fetch a single article by slug', () => {
      const mockArticle = createMockContent({ slug: 'my-article' });

      service.getArticleBySlug('my-article').subscribe((article) => {
        expect(article).toEqual(mockArticle);
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/my-article'),
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: mockArticle });
    });

    it('should propagate error to subscriber on failure', () => {
      service.getArticleBySlug('not-found').subscribe({
        error: (err) => {
          expect(err).toBeTruthy();
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/not-found'));
      req.flush('Not found', { status: 404, statusText: 'Not Found' });
    });
  });

  describe('createArticle', () => {
    it('should POST to admin contents endpoint with type article', () => {
      const request = {
        slug: 'new-article',
        title: 'New Article',
        type: 'article' as const,
      };
      const mockResponse = createMockContent({ slug: 'new-article', title: 'New Article' });

      service.createArticle(request).subscribe((article) => {
        expect(article.title).toBe('New Article');
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/admin/knowledge/content'));
      expect(req.request.method).toBe('POST');
      expect(req.request.body.type).toBe('article');
      req.flush({ data: mockResponse });
    });
  });

  describe('updateArticle', () => {
    it('should PUT to admin contents endpoint with id', () => {
      const mockResponse = createMockContent({ title: 'Updated Title' });

      service.updateArticle('content-001', { title: 'Updated Title' }).subscribe((article) => {
        expect(article.title).toBe('Updated Title');
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/admin/knowledge/content/content-001'),
      );
      expect(req.request.method).toBe('PUT');
      req.flush({ data: mockResponse });
    });
  });

  describe('deleteArticle', () => {
    it('should DELETE admin contents endpoint with id', () => {
      service.deleteArticle('content-001').subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/admin/knowledge/content/content-001'),
      );
      expect(req.request.method).toBe('DELETE');
      req.flush(null);
    });
  });

  describe('publishArticle', () => {
    it('should POST to publish endpoint', () => {
      const mockResponse = createMockContent({ status: 'published' });

      service.publishArticle('content-001').subscribe((article) => {
        expect(article.status).toBe('published');
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/admin/knowledge/content/content-001/publish'),
      );
      expect(req.request.method).toBe('POST');
      req.flush({ data: mockResponse });
    });
  });
});
