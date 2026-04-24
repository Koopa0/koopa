import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { BookmarkService } from './bookmark.service';
import type { BookmarkDetail } from '../models/workbench.model';

const mockBookmark: BookmarkDetail = {
  id: 'bm-1',
  url: 'https://example.com/article',
  url_hash: 'sha256...',
  slug: 'go-errgroup-patterns',
  title: 'Go errgroup patterns',
  excerpt: 'A practical guide to errgroup.',
  note: 'Worth re-reading when revisiting concurrency.',
  capture_channel: 'manual',
  source_feed_entry_id: null,
  curated_by: 'human',
  curated_at: '2026-04-15T08:00:00Z',
  is_public: false,
  published_at: null,
  topics: [],
  tags: ['go', 'concurrency'],
  created_at: '2026-04-15T08:00:00Z',
  updated_at: '2026-04-15T08:00:00Z',
  host: 'example.com',
  source_feed_name: null,
};

describe('BookmarkService', () => {
  let service: BookmarkService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(BookmarkService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch a bookmark by id', () => {
    service.get('bm-1').subscribe((res) => {
      expect(res.url).toBe('https://example.com/article');
      expect(res.tags).toContain('go');
    });

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/knowledge/bookmarks/bm-1'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockBookmark });
  });
});
