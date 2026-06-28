import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  provideHttpClientTesting,
  HttpTestingController,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { TopicDetailComponent } from './topic-detail';
import type {
  ApiContent,
  ApiPaginationMeta,
  ApiTopic,
} from '../../core/models';

function buildMockTopic(overrides: Partial<ApiTopic> = {}): ApiTopic {
  return {
    id: 'topic-1',
    slug: 'go',
    name: 'Go',
    description: 'The Go topic',
    icon: '',
    content_count: 2,
    sort_order: 1,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

function buildMockContent(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'c-1',
    slug: 'a-piece',
    title: 'A Piece',
    excerpt: 'An excerpt',
    body: '',
    type: 'article',
    status: 'published',
    topics: [{ id: 'topic-1', slug: 'go', name: 'Go' }],
    cover_image: null,
    series_id: null,
    series_order: null,
    is_public: true,
    ai_metadata: null,
    reading_time_min: 5,
    published_at: '2026-01-15T00:00:00Z',
    created_at: '2026-01-15T00:00:00Z',
    updated_at: '2026-01-15T00:00:00Z',
    ...overrides,
  };
}

function buildMockMeta(
  overrides: Partial<ApiPaginationMeta> = {},
): ApiPaginationMeta {
  return { total: 2, page: 1, per_page: 12, total_pages: 1, ...overrides };
}

describe('TopicDetailComponent', () => {
  let component: TopicDetailComponent;
  let fixture: ComponentFixture<TopicDetailComponent>;
  let httpTesting: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TopicDetailComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpTesting = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(TopicDetailComponent);
    component = fixture.componentInstance;
  });

  function flushTopic(
    topic: ApiTopic,
    contents: ApiContent[],
    meta: ApiPaginationMeta = buildMockMeta({ total: contents.length }),
  ): void {
    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/topics/') && r.method === 'GET',
    );
    req.flush({ data: { topic, contents }, meta });
  }

  it('should render the topic head and a row per piece', () => {
    fixture.componentRef.setInput('slug', 'go');
    fixture.detectChanges();
    flushTopic(buildMockTopic(), [
      buildMockContent({ id: '1', title: 'First Go piece' }),
      buildMockContent({ id: '2', title: 'Second Go piece', type: 'til' }),
    ]);
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Go');
    const rows = el.querySelectorAll('[data-testid="topic-row"]');
    expect(rows.length).toBe(2);
    expect(rows[0].getAttribute('href')).toBe('/articles/a-piece');
  });

  it('should show the piece count and one type swatch per type in the head', () => {
    fixture.componentRef.setInput('slug', 'go');
    fixture.detectChanges();
    flushTopic(buildMockTopic(), [
      buildMockContent({ id: '1', type: 'article' }),
      buildMockContent({ id: '2', type: 'til' }),
      buildMockContent({ id: '3', type: 'til' }),
    ]);
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    const meta = el.querySelector('.ed-metaline');
    expect(meta?.textContent).toContain('3 pieces');
    // One coloured dot per distinct type present (article + til = 2),
    // not one per piece (3) nor one per known type (5).
    expect(meta?.querySelectorAll('.ed-dot').length).toBe(2);
  });

  it('should filter rows by type when a tab is selected', () => {
    fixture.componentRef.setInput('slug', 'go');
    fixture.detectChanges();
    flushTopic(buildMockTopic(), [
      buildMockContent({ id: '1', title: 'An article', type: 'article' }),
      buildMockContent({ id: '2', title: 'A til', type: 'til' }),
    ]);
    fixture.detectChanges();

    component['selectType']('til');
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    const rows = el.querySelectorAll('[data-testid="topic-row"]');
    expect(rows.length).toBe(1);
    expect(el.textContent).toContain('A til');
    expect(el.textContent).not.toContain('An article');
  });

  it('should show the not-found state on 404', () => {
    fixture.componentRef.setInput('slug', 'missing');
    fixture.detectChanges();

    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/topics/') && r.method === 'GET',
    );
    req.flush('Not found', { status: 404, statusText: 'Not Found' });
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Topic not found');
    expect(component['isNotFound']()).toBe(true);
  });

  it('should show the error state on a 500', () => {
    fixture.componentRef.setInput('slug', 'go');
    fixture.detectChanges();

    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/topics/') && r.method === 'GET',
    );
    req.flush('Server error', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Failed to load topic content');
    expect(component['error']()).not.toBeNull();
  });
});
