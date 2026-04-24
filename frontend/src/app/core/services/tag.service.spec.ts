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

    it('should propagate error to subscriber', () => {
      service.getContentsByTag('Angular').subscribe({
        error: (err) => {
          expect(err).toBeTruthy();
        },
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents') && r.params.get('tag') === 'Angular',
      );
      req.flush('Server error', { status: 500, statusText: 'Internal Server Error' });
    });
  });
});
