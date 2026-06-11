import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { ContentPreviewOverlayComponent } from './preview-overlay.component';

describe('ContentPreviewOverlayComponent', () => {
  let fixture: ComponentFixture<ContentPreviewOverlayComponent>;

  function create(
    inputs: { slug?: string; type?: string; live?: boolean } = {},
  ): void {
    fixture = TestBed.createComponent(ContentPreviewOverlayComponent);
    fixture.componentRef.setInput('slug', inputs.slug ?? 'value-semantics');
    fixture.componentRef.setInput('type', inputs.type ?? 'article');
    fixture.componentRef.setInput('live', inputs.live ?? false);
    fixture.detectChanges();
  }

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  it('should point the iframe at the /preview/:slug route', () => {
    create({ slug: 'value-semantics' });

    const iframe = el().querySelector<HTMLIFrameElement>(
      '[data-testid="preview-iframe"]',
    );
    expect(iframe?.getAttribute('src')).toBe('/preview/value-semantics');
  });

  it('should URI-encode the slug in the iframe src', () => {
    create({ slug: 'a b' });

    const iframe = el().querySelector<HTMLIFrameElement>(
      '[data-testid="preview-iframe"]',
    );
    expect(iframe?.getAttribute('src')).toBe('/preview/a%20b');
  });

  it('should display the public URL form for the content type', () => {
    create({ slug: 'my-post', type: 'til' });

    expect(
      el().querySelector('[data-testid="preview-url"]')?.textContent,
    ).toContain('koopa0.dev/til/my-post');
  });

  it('should label the preview draft when not live and live when published', () => {
    create({ live: false });
    expect(
      el().querySelector('[data-testid="preview-note"]')?.textContent,
    ).toContain('draft preview');

    create({ live: true });
    expect(
      el().querySelector('[data-testid="preview-note"]')?.textContent,
    ).toContain('live preview');
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
