import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { NoteService } from './note.service';
import type { ApiContent, ApiPaginationMeta } from '../models';

function createMockContent(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'note-001',
    slug: 'test-note',
    title: 'Test Note',
    body: '# Note',
    excerpt: 'A test note',
    type: 'note',
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
    reading_time: 2,
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

describe('NoteService', () => {
  let service: NoteService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(NoteService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('getNotes', () => {
    it('should fetch notes and map response correctly', () => {
      const mockNote = createMockContent();
      const mockMeta = createMockMeta();

      service.getNotes().subscribe((response) => {
        expect(response.notes).toEqual([mockNote]);
        expect(response.meta).toEqual(mockMeta);
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/by-type/note'),
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [mockNote], meta: mockMeta });
    });

    it('should pass page and perPage parameters', () => {
      service.getNotes(3, 15).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/by-type/note') &&
        r.params.get('page') === '3' &&
        r.params.get('per_page') === '15',
      );
      req.flush({ data: [], meta: createMockMeta({ page: 3, per_page: 15 }) });
    });

    it('should propagate error to subscriber', () => {
      service.getNotes().subscribe({
        error: (err) => {
          expect(err).toBeTruthy();
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/by-type/note'));
      req.flush('Server error', { status: 500, statusText: 'Internal Server Error' });
    });
  });

  describe('getBySlug', () => {
    it('should fetch a single note by slug', () => {
      const mockNote = createMockContent({ slug: 'my-note' });

      service.getBySlug('my-note').subscribe((note) => {
        expect(note).toEqual(mockNote);
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/my-note'),
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: mockNote });
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
