import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { LatestFeedComponent } from './latest-feed.component';
import type { ApiContent } from '../../../core/models';

function createMockContent(
  overrides: Record<string, unknown> = {},
): ApiContent {
  return {
    id: '1',
    slug: 'test-article',
    title: 'Test Article',
    body: 'Some article content here.',
    excerpt: 'A test article excerpt',
    type: 'article',
    status: 'published',
    tags: ['angular'],
    topics: [],
    cover_image: null,
    source: null,
    source_type: null,
    series_id: null,
    series_order: null,
    review_level: 'auto',
    visibility: 'public',
    ai_metadata: null,
    reading_time: 5,
    published_at: '2026-01-15T00:00:00Z',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  } as ApiContent;
}

describe('LatestFeedComponent', () => {
  let component: LatestFeedComponent;
  let fixture: ComponentFixture<LatestFeedComponent>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [LatestFeedComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(LatestFeedComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    fixture.detectChanges();

    const req = httpMock.expectOne((r) => r.url.includes('/api/contents'));
    req.flush({
      data: [],
      meta: { page: 1, per_page: 18, total: 0, total_pages: 0 },
    });

    expect(component).toBeTruthy();
  });

  it('should show loading state initially', () => {
    expect(component['isLoading']()).toBe(true);

    fixture.detectChanges();

    const req = httpMock.expectOne((r) => r.url.includes('/api/contents'));
    req.flush({
      data: [],
      meta: { page: 1, per_page: 18, total: 0, total_pages: 0 },
    });
  });

  it('should display feed entries after loading', () => {
    fixture.detectChanges();

    const mockContents = [
      createMockContent({
        id: '1',
        slug: 'article-1',
        title: 'First Article',
        type: 'article',
      }),
      createMockContent({
        id: '2',
        slug: 'build-1',
        title: 'Build Log 1',
        type: 'build-log',
      }),
      createMockContent({
        id: '3',
        slug: 'til-1',
        title: 'TIL 1',
        type: 'til',
      }),
    ];

    const req = httpMock.expectOne((r) => r.url.includes('/api/contents'));
    req.flush({
      data: mockContents,
      meta: { page: 1, per_page: 18, total: 3, total_pages: 1 },
    });

    expect(component['isLoading']()).toBe(false);
    expect(component['feedEntries']().length).toBe(3);
    expect(component['feedEntries']()[0].title).toBe('First Article');
  });
});
