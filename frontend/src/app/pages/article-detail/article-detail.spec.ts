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

  /** Let the related rxResource issue its request, then render. */
  async function settle(): Promise<void> {
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  /** Drain the below-the-fold related request (full mode only). */
  function flushRelated(): void {
    httpTesting
      .expectOne(
        (r) =>
          r.url.includes('/api/contents/related/') && r.method === 'GET',
      )
      .flush({ data: [] });
  }

  it('should create', async () => {
    fixture.componentRef.setInput('article', buildMockContent());
    fixture.detectChanges();
    await settle();
    flushRelated();

    expect(component).toBeTruthy();
  });

  it('should render the back link, title, meta line, and prose in full mode', async () => {
    fixture.componentRef.setInput('article', buildMockContent());
    fixture.detectChanges();
    await settle();
    flushRelated();
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    // The quiet mono back link points at the archive.
    const crumb = el.querySelector('a.ed-crumb');
    expect(crumb?.getAttribute('href')).toBe('/articles');
    // One inline mono meta line carries type, date, and reading time.
    expect(el.querySelector('.ed-metaline')).toBeTruthy();
    // The reading column rendered the title, prose body, and reading time.
    expect(el.querySelector('.ed-prose')).toBeTruthy();
    expect(el.textContent).toContain('Test Article');
    expect(el.textContent).toContain('5 min');
    // The on-this-page TOC rail was dropped from this surface.
    expect(el.querySelector('app-table-of-contents')).toBeNull();
  });

  it.each<ContentType>(['article', 'essay', 'build-log', 'til', 'digest'])(
    'should render %s content on the same reading surface',
    async (type) => {
      fixture.componentRef.setInput(
        'article',
        buildMockContent({ type, slug: `some-${type}`, title: `A ${type}` }),
      );
      fixture.detectChanges();
      await settle();
      flushRelated();
      await settle();

      const el = fixture.nativeElement as HTMLElement;
      expect(el.textContent).toContain(`A ${type}`);
      // The mono meta line shows the raw content type (e.g. "build-log").
      expect(el.querySelector('.ed-metaline')?.textContent).toContain(type);
    },
  );

  it('should hide the back link, TOC, and read-next in preview mode', async () => {
    fixture.componentRef.setInput('article', buildMockContent());
    fixture.componentRef.setInput('preview', true);
    fixture.detectChanges();
    await settle();
    httpTesting.verify(); // no related request in preview (resource idle)

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('a.ed-crumb')).toBeNull();
    expect(el.querySelector('app-table-of-contents')).toBeNull();
    expect(el.querySelector('app-related-articles')).toBeNull();
    // The chrome-less column keeps the title, dek, and the mended seam.
    expect(el.querySelector('.ed-seam')).toBeTruthy();
    expect(el.textContent).toContain('Test Article');
  });

  it('should mark the page noindex in preview mode', async () => {
    fixture.componentRef.setInput('article', buildMockContent());
    fixture.componentRef.setInput('preview', true);
    fixture.detectChanges();
    await settle();

    const robots = document.querySelector('meta[name="robots"]');
    expect(robots?.getAttribute('content')).toBe('noindex, nofollow');
  });
});
