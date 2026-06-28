import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RelatedArticlesComponent } from './related-articles.component';
import type { ApiContent } from '../../core/models';

function createMockContent(
  overrides: Partial<ApiContent> = {},
): ApiContent {
  return {
    id: 'c1',
    slug: 'test',
    title: 'Test',
    body: '',
    excerpt: 'Excerpt',
    type: 'article',
    status: 'published',
    topics: [],
    cover_image: null,
    series_id: null,
    series_order: null,
    is_public: true,
    reading_time_min: 3,
    published_at: '2026-01-01T00:00:00Z',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  } as ApiContent;
}

describe('RelatedArticlesComponent', () => {
  let fixture: ComponentFixture<RelatedArticlesComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [RelatedArticlesComponent],
      providers: [provideRouter([])],
    }).compileComponents();
    fixture = TestBed.createComponent(RelatedArticlesComponent);
  });

  it('should create', () => {
    fixture.detectChanges();
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('should not render when articles empty', () => {
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('section')).toBeNull();
  });

  it('should render articles when provided', () => {
    fixture.componentRef.setInput('articles', [
      createMockContent(),
      createMockContent({ id: 'c2', slug: 'test2', title: 'Test 2' }),
    ]);
    fixture.detectChanges();
    const links = fixture.nativeElement.querySelectorAll('a');
    expect(links.length).toBe(2);
  });

  it('should cap the list at two read-next rows', () => {
    fixture.componentRef.setInput('articles', [
      createMockContent(),
      createMockContent({ id: 'c2', slug: 'test2', title: 'Test 2' }),
      createMockContent({ id: 'c3', slug: 'test3', title: 'Test 3' }),
    ]);
    fixture.detectChanges();
    const links = fixture.nativeElement.querySelectorAll('a');
    expect(links.length).toBe(2);
  });

  it('should route every type to the single reading surface', () => {
    fixture.componentRef.setInput('articles', [
      createMockContent({ slug: 'a-til', type: 'til' }),
    ]);
    fixture.detectChanges();
    const link = fixture.nativeElement.querySelector('a');
    expect(link?.getAttribute('href')).toBe('/articles/a-til');
  });
});
