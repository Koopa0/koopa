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

  it('should have loading signal initialized to false', () => {
    expect(service.loading()).toBe(false);
  });

  it('should have errorMessage signal initialized to null', () => {
    expect(service.errorMessage()).toBeNull();
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
        r.url.includes('/api/contents/type/note'),
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: [mockNote], meta: mockMeta });
    });

    it('should set loading to true when called and false after response', () => {
      service.getNotes().subscribe();
      expect(service.loading()).toBe(true);

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/type/note'));
      req.flush({ data: [], meta: createMockMeta() });

      expect(service.loading()).toBe(false);
    });

    it('should pass page and perPage parameters', () => {
      service.getNotes(3, 15).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/contents/type/note') &&
        r.params.get('page') === '3' &&
        r.params.get('per_page') === '15',
      );
      req.flush({ data: [], meta: createMockMeta({ page: 3, per_page: 15 }) });
    });

    it('should set error message on failure', () => {
      service.getNotes().subscribe({
        error: () => {
          // expected
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/contents/type/note'));
      req.flush('Server error', { status: 500, statusText: 'Internal Server Error' });

      expect(service.loading()).toBe(false);
      expect(service.errorMessage()).toBe('Failed to load notes');
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

      expect(service.errorMessage()).toBe('Note not found');
      expect(service.loading()).toBe(false);
    });
  });
});
