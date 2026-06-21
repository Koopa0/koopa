import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  provideHttpClientTesting,
  HttpTestingController,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { ArticleDetailComponent } from './article-detail';
import { contentTypeLabelEn } from '../../core/models';
import type { ApiContent, ContentType } from '../../core/models';

function buildMockContent(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'test-1',
    slug: 'test-article',
    title: 'Test Article',
    excerpt: 'A test excerpt',
    body: '## Section one\n\nBody text.',
    type: 'article',
    status: 'published',
    tags: ['go'],
    topics: [],
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

describe('ArticleDetailComponent', () => {
  let component: ArticleDetailComponent;
  let fixture: ComponentFixture<ArticleDetailComponent>;
  let httpTesting: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ArticleDetailComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpTesting = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(ArticleDetailComponent);
    component = fixture.componentInstance;
  });

  function flushDetail(content: ApiContent): void {
    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/contents/') && r.method === 'GET',
    );
    req.flush({ data: content });
  }

  function flushRelated(): void {
    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/contents/related/') && r.method === 'GET',
    );
    req.flush({ data: [] });
  }

  it('should create', () => {
    fixture.componentRef.setInput('slug', 'test-article');
    fixture.detectChanges();
    expect(component).toBeTruthy();
    flushDetail(buildMockContent());
    flushRelated();
  });

  it('should render breadcrumbs, meta, and TOC rail in full mode', () => {
    fixture.componentRef.setInput('slug', 'test-article');
    fixture.detectChanges();
    flushDetail(buildMockContent());
    flushRelated();
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('nav[aria-label="Breadcrumb"]')).toBeTruthy();
    expect(el.querySelector('app-table-of-contents')).toBeTruthy();
    expect(el.textContent).toContain('Test Article');
    expect(el.textContent).toContain('5 min');
  });

  it.each<ContentType>(['article', 'essay', 'build-log', 'til', 'digest'])(
    'should render %s content on the same reading surface',
    (type) => {
      fixture.componentRef.setInput('slug', `some-${type}`);
      fixture.detectChanges();
      flushDetail(
        buildMockContent({ type, slug: `some-${type}`, title: `A ${type}` }),
      );
      flushRelated();
      fixture.detectChanges();

      const el = fixture.nativeElement as HTMLElement;
      expect(el.textContent).toContain(`A ${type}`);
      // The reading surface shows the human type label (e.g. "Build Log").
      expect(el.textContent).toContain(contentTypeLabelEn(type));
    },
  );

  it('should hide breadcrumbs, TOC, and read-next in preview mode', () => {
    fixture.componentRef.setInput('slug', 'test-article');
    fixture.componentRef.setInput('preview', true);
    fixture.detectChanges();
    flushDetail(buildMockContent());
    httpTesting.verify(); // no related request in preview
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('nav[aria-label="Breadcrumb"]')).toBeNull();
    expect(el.querySelector('app-table-of-contents')).toBeNull();
    expect(el.querySelector('app-related-articles')).toBeNull();
    expect(el.textContent).toContain('Test Article');
  });

  it('should show the error state when the detail request fails (500)', () => {
    fixture.componentRef.setInput('slug', 'broken');
    fixture.detectChanges();

    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/contents/') && r.method === 'GET',
    );
    req.flush('Server error', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Failed to load');
    expect(component['error']()).toBe('Failed to load article');
  });

  it('should mark the page noindex in preview mode', () => {
    fixture.componentRef.setInput('slug', 'test-article');
    fixture.componentRef.setInput('preview', true);
    fixture.detectChanges();
    flushDetail(buildMockContent());
    fixture.detectChanges();

    const robots = document.querySelector('meta[name="robots"]');
    expect(robots?.getAttribute('content')).toBe('noindex, nofollow');
  });
});
