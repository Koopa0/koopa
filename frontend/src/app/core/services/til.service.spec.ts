import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TilService } from './til.service';
import type { ApiContent, ApiPaginationMeta } from '../models';

function createMockContent(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'til-001',
    slug: 'test-til',
    title: 'Test TIL',
    body: '# TIL',
    excerpt: 'A test TIL entry',
    type: 'til',
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
    reading_time: 1,
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

describe('TilService', () => {
  let service: TilService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(TilService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('getTils', () => {
    it('should fetch TILs and map response correctly', () => {
      const mockTil = createMockContent();
      const mockMeta = createMockMeta();

      service.getTils().subscribe((response) => {
        expect(response.tils).toEqual([mockTil]);
        expect(response.meta).toEqual(mockMeta);
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/type/til'),
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [mockTil], meta: mockMeta });
    });

    it('should pass page and perPage parameters', () => {
      service.getTils(2, 10).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/type/til') &&
        r.params.get('page') === '2' &&
        r.params.get('per_page') === '10',
      );
      req.flush({ data: [], meta: createMockMeta({ page: 2, per_page: 10 }) });
    });

    it('should propagate error to subscriber', () => {
      service.getTils().subscribe({
        error: (err) => {
          expect(err).toBeTruthy();
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/type/til'));
      req.flush('Server error', { status: 500, statusText: 'Internal Server Error' });
    });
  });

  describe('getBySlug', () => {
    it('should fetch a single TIL by slug', () => {
      const mockTil = createMockContent({ slug: 'my-til' });

      service.getBySlug('my-til').subscribe((til) => {
        expect(til).toEqual(mockTil);
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/my-til'),
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: mockTil });
    });

    it('should propagate error to subscriber on failure', () => {
      service.getBySlug('not-found').subscribe({
        error: (err) => {
          expect(err).toBeTruthy();
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/not-found'));
      req.flush('Not found', { status: 404, statusText: 'Not Found' });
    });
  });
});
