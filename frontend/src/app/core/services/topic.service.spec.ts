import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { TopicService } from './topic.service';
import type { ApiTopic, ApiContent, ApiPaginationMeta } from '../models';

function createMockTopic(overrides: Partial<ApiTopic> = {}): ApiTopic {
  return {
    id: 'topic-001',
    slug: 'angular',
    name: 'Angular',
    description: 'Angular framework',
    icon: 'angular',
    content_count: 5,
    sort_order: 1,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

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

describe('TopicService', () => {
  let service: TopicService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(TopicService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('getAllTopics', () => {
    it('should fetch all topics', () => {
      const mockTopics = [
        createMockTopic({ slug: 'angular', name: 'Angular' }),
        createMockTopic({ id: 'topic-002', slug: 'go', name: 'Go' }),
      ];

      service.getAllTopics().subscribe((topics) => {
        expect(topics).toHaveLength(2);
        expect(topics[0].slug).toBe('angular');
        expect(topics[1].slug).toBe('go');
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/topics'));
      expect(req.request.method).toBe('GET');
      req.flush({ data: mockTopics });
    });

    it('should return empty array when no topics exist', () => {
      service.getAllTopics().subscribe((topics) => {
        expect(topics).toHaveLength(0);
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/topics'));
      req.flush({ data: [] });
    });
  });

  describe('getTopicBySlug', () => {
    it('should fetch topic with its contents by slug', () => {
      const mockTopic = createMockTopic({ slug: 'angular' });
      const mockContent = createMockContent();
      const mockMeta = createMockMeta();

      service.getTopicBySlug('angular').subscribe((result) => {
        expect(result.topic.slug).toBe('angular');
        expect(result.contents).toHaveLength(1);
        expect(result.meta).toEqual(mockMeta);
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/topics/angular'));
      expect(req.request.method).toBe('GET');
      req.flush({
        data: { topic: mockTopic, contents: [mockContent] },
        meta: mockMeta,
      });
    });

    it('should pass pagination parameters', () => {
      service.getTopicBySlug('go', { page: 2, perPage: 5 }).subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/topics/go') &&
        r.params.get('page') === '2' &&
        r.params.get('per_page') === '5',
      );
      req.flush({
        data: { topic: createMockTopic({ slug: 'go' }), contents: [] },
        meta: createMockMeta({ page: 2, per_page: 5 }),
      });
    });

    it('should propagate error on failure', () => {
      service.getTopicBySlug('not-found').subscribe({
        error: (err: { status: number }) => {
          expect(err.status).toBe(404);
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/topics/not-found'));
      req.flush('Not Found', { status: 404, statusText: 'Not Found' });
    });
  });
});
