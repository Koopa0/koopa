import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { PostRowComponent } from './post-row.component';
import type { ApiContent } from '../../core/models';

function buildMockContent(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'content-1',
    slug: 'value-semantics-in-go',
    title: 'Value Semantics in Go',
    excerpt: 'Why copies are not the enemy.',
    body: '',
    type: 'article',
    status: 'published',
    tags: ['go'],
    topics: [],
    cover_image: null,
    series_id: null,
    series_order: null,
    is_public: true,
    ai_metadata: null,
    reading_time_min: 7,
    published_at: '2026-05-30T00:00:00Z',
    created_at: '2026-05-30T00:00:00Z',
    updated_at: '2026-05-30T00:00:00Z',
    ...overrides,
  };
}

describe('PostRowComponent', () => {
  let fixture: ComponentFixture<PostRowComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PostRowComponent],
      providers: [provideRouter([])],
    }).compileComponents();

    fixture = TestBed.createComponent(PostRowComponent);
  });

  function render(content: ApiContent): HTMLElement {
    fixture.componentRef.setInput('content', content);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('should render the title, type, and reading time when given a content', () => {
    const el = render(buildMockContent());

    expect(el.textContent).toContain('Value Semantics in Go');
    expect(el.textContent).toContain('article');
    expect(el.textContent).toContain('7 min');
    expect(el.textContent).toContain('Why copies are not the enemy.');
  });

  it('should link to the single reading surface at /articles/:slug', () => {
    const el = render(buildMockContent({ slug: 'my-til', type: 'til' }));

    const row = el.querySelector('[data-testid="index-row"]');
    expect(row?.getAttribute('href')).toBe('/articles/my-til');
  });

  it('should omit the date separator when published_at is null', () => {
    const el = render(buildMockContent({ published_at: null }));

    expect(el.textContent).not.toContain('·');
  });
});
