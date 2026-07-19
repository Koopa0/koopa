import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { ContentPreviewOverlayComponent } from './preview-overlay.component';
import type { ApiContent } from '../../../../core/models/api.model';

function contentPayload(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'abc-1',
    slug: 'value-semantics',
    title: 'Value semantics in Go',
    body: '# Heading\n\nPersisted body.',
    excerpt: 'A persisted excerpt.',
    type: 'article',
    status: 'draft',
    topics: [],
    cover_image: null,
    series_id: null,
    series_order: null,
    is_public: false,
    reading_time_min: 3,
    published_at: null,
    created_at: '2026-06-01T00:00:00Z',
    updated_at: '2026-06-02T00:00:00Z',
    ...overrides,
  };
}

describe('ContentPreviewOverlayComponent', () => {
  let fixture: ComponentFixture<ContentPreviewOverlayComponent>;

  function create(overrides: Partial<ApiContent> = {}): void {
    fixture = TestBed.createComponent(ContentPreviewOverlayComponent);
    fixture.componentRef.setInput('content', contentPayload(overrides));
    fixture.detectChanges();
  }

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  it('should render the persisted content inline without an iframe', () => {
    create();

    expect(el().querySelector('[data-testid="preview-iframe"]')).toBeNull();
    expect(el().querySelector('[data-testid="preview-content"]')).toBeTruthy();
    expect(el().textContent).toContain('Value semantics in Go');
    expect(el().textContent).toContain('Persisted body.');
  });

  it('should display the canonical /articles public URL regardless of type', () => {
    create({ slug: 'my-post', type: 'til' });

    expect(
      el().querySelector('[data-testid="preview-url"]')?.textContent,
    ).toContain('koopa0.dev/articles/my-post');
  });

  it('should distinguish saved non-public content from a live snapshot', () => {
    create();
    expect(
      el().querySelector('[data-testid="preview-note"]')?.textContent,
    ).toContain('not public');

    create({ status: 'published', is_public: true });
    expect(
      el().querySelector('[data-testid="preview-note"]')?.textContent,
    ).toContain('live on the public site');
  });

  it('should emit closed on scrim mousedown but not on frame mousedown', () => {
    create();
    let closedCount = 0;
    fixture.componentInstance.closed.subscribe(() => closedCount++);

    el()
      .querySelector<HTMLElement>('[data-testid="preview-frame"]')
      ?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
    expect(closedCount).toBe(0);

    el()
      .querySelector<HTMLElement>('[data-testid="preview-scrim"]')
      ?.dispatchEvent(new MouseEvent('mousedown'));
    expect(closedCount).toBe(1);
  });

  it('should emit closed when Escape is pressed on the document', () => {
    create();
    let closed = false;
    fixture.componentInstance.closed.subscribe(() => (closed = true));

    document.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }),
    );
    expect(closed).toBe(true);
  });

  it('should emit closed when the Close button is clicked', () => {
    create();
    let closed = false;
    fixture.componentInstance.closed.subscribe(() => (closed = true));

    el()
      .querySelector<HTMLButtonElement>('[data-testid="preview-close"]')
      ?.click();
    expect(closed).toBe(true);
  });
});
