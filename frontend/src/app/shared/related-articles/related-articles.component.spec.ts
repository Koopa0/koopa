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
    tags: [],
    topics: [],
    cover_image: null,
    source: null,
    source_type: null,
    series_id: null,
    series_order: null,
    is_public: true,
    ai_metadata: null,
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
});
