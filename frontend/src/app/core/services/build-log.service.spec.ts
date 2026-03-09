import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { BuildLogService } from './build-log.service';
import type { ApiContent, ApiPaginationMeta } from '../models';

function createMockContent(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'bl-001',
    slug: 'test-build-log',
    title: 'Test Build Log',
    body: '# Build Log',
    excerpt: 'A test build log',
    type: 'build-log',
    status: 'published',
    tags: ['Go'],
    topics: [],
    cover_image: null,
    source: null,
    source_type: null,
    series_id: null,
    series_order: null,
    review_level: 'auto',
    ai_metadata: null,
    reading_time: 3,
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

describe('BuildLogService', () => {
  let service: BuildLogService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(BuildLogService);
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

  describe('getBuildLogs', () => {
    it('should fetch build logs and map response correctly', () => {
      const mockBuildLog = createMockContent();
      const mockMeta = createMockMeta();

      service.getBuildLogs().subscribe((response) => {
        expect(response.buildLogs).toEqual([mockBuildLog]);
        expect(response.meta).toEqual(mockMeta);
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/type/build-log'),
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [mockBuildLog], meta: mockMeta });
    });

    it('should set loading to true when called and false after response', () => {
      service.getBuildLogs().subscribe();
      expect(service.loading()).toBe(true);

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/type/build-log'));
      req.flush({ data: [], meta: createMockMeta() });

      expect(service.loading()).toBe(false);
    });

    it('should pass page and perPage parameters', () => {
      service.getBuildLogs(2, 5).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/type/build-log') &&
        r.params.get('page') === '2' &&
        r.params.get('per_page') === '5',
      );
      req.flush({ data: [], meta: createMockMeta({ page: 2, per_page: 5 }) });
    });

    it('should set error message on failure', () => {
      service.getBuildLogs().subscribe({
        error: () => {
          // expected
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/type/build-log'));
      req.flush('Server error', { status: 500, statusText: 'Internal Server Error' });

      expect(service.loading()).toBe(false);
      expect(service.errorMessage()).toBe('Failed to load build logs');
    });
  });

  describe('getBySlug', () => {
    it('should fetch a single build log by slug', () => {
      const mockBuildLog = createMockContent({ slug: 'my-build-log' });

      service.getBySlug('my-build-log').subscribe((buildLog) => {
        expect(buildLog).toEqual(mockBuildLog);
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/my-build-log'),
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: mockBuildLog });
    });

    it('should set loading state during request', () => {
      service.getBySlug('test').subscribe();
      expect(service.loading()).toBe(true);

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/test'));
      req.flush({ data: createMockContent() });

      expect(service.loading()).toBe(false);
    });

    it('should set error on failure', () => {
      service.getBySlug('not-found').subscribe({
        error: () => {
          // expected
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/not-found'));
      req.flush('Not found', { status: 404, statusText: 'Not Found' });

      expect(service.errorMessage()).toBe('Build log not found');
      expect(service.loading()).toBe(false);
    });
  });
});
