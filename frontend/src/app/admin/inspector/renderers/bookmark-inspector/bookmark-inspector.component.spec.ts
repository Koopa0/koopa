import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { provideRouter } from '@angular/router';
import { BookmarkInspectorComponent } from './bookmark-inspector.component';
import type { BookmarkDetail } from '../../../../core/models/workbench.model';

const baseBookmark: BookmarkDetail = {
  id: 'bm-1',
  url: 'https://example.com/articles/latency-patterns',
  url_hash: 'a'.repeat(64),
  slug: 'latency-patterns',
  title: 'Latency Patterns Deep Dive',
  excerpt: 'A practical guide to handling latency in distributed systems.',
  note: 'Worth re-reading when revisiting exactly-once semantics in NATS.',
  capture_channel: 'manual',
  source_feed_entry_id: null,
  curated_by: 'human',
  curated_at: '2026-04-15T08:00:00Z',
  is_public: true,
  published_at: '2026-04-15T08:00:00Z',
  topics: [
    { id: 't1', slug: 'distributed-systems', name: 'Distributed Systems' },
  ],
  tags: ['nats', 'latency'],
  created_at: '2026-04-15T08:00:00Z',
  updated_at: '2026-04-15T08:00:00Z',
  host: 'example.com',
  source_feed_name: null,
};

describe('BookmarkInspectorComponent', () => {
  let fixture: ComponentFixture<BookmarkInspectorComponent>;
  let httpMock: HttpTestingController;

  function setupFixture(): void {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
        provideRouter([]),
      ],
    });
    fixture = TestBed.createComponent(BookmarkInspectorComponent);
    httpMock = TestBed.inject(HttpTestingController);
  }

  function flushAll(id: string, response: BookmarkDetail | null): void {
    const reqs = httpMock.match((r) =>
      r.url.includes(`/api/admin/knowledge/bookmarks/${id}`),
    );
    expect(reqs.length).toBeGreaterThan(0);
    for (const r of reqs) {
      if (response === null) {
        r.flush(null, { status: 500, statusText: 'Internal Server Error' });
      } else {
        r.flush({ data: response });
      }
    }
  }

  async function loadAndSettle(b: BookmarkDetail | null): Promise<void> {
    fixture.componentRef.setInput('id', baseBookmark.id);
    fixture.detectChanges();
    flushAll(baseBookmark.id, b);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should render title + host + Public subtitle when public', async () => {
    setupFixture();
    await loadAndSettle(baseBookmark);

    const el = fixture.nativeElement as HTMLElement;
    expect(
      el.querySelector('[data-testid="bookmark-title"]')?.textContent,
    ).toContain('Latency Patterns Deep Dive');
    const subtitle = el.querySelector('[data-testid="bookmark-subtitle"]');
    expect(subtitle?.textContent).toContain('example.com');
    expect(el.querySelector('[data-testid="bookmark-is-public"]')).toBeTruthy();
  });

  it('should render Private label when is_public is false', async () => {
    setupFixture();
    await loadAndSettle({
      ...baseBookmark,
      is_public: false,
      published_at: null,
    });

    const priv = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-is-private"]',
    );
    expect(priv?.textContent?.trim()).toBe('Private');
  });

  it('should render external URL with proper security attrs and target=_blank', async () => {
    setupFixture();
    await loadAndSettle(baseBookmark);

    const link = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-external-link"]',
    ) as HTMLAnchorElement;
    expect(link).toBeTruthy();
    expect(link.getAttribute('target')).toBe('_blank');
    expect(link.getAttribute('rel')).toBe('noopener noreferrer nofollow');
    expect(link.getAttribute('href')).toBe(baseBookmark.url);
    expect(link.getAttribute('title')).toBe(baseBookmark.url);
  });

  it('should middle-ellipsis truncate long URLs in display, full URL in href/title', async () => {
    setupFixture();
    const longUrl =
      'https://very.long.domain.example.com/some/very/deep/path/to/an/article/with/an/extremely-long-slug-that-exceeds-sixty-characters';
    await loadAndSettle({
      ...baseBookmark,
      url: longUrl,
      host: 'very.long.domain.example.com',
    });

    const link = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-external-link"]',
    ) as HTMLAnchorElement;
    const display = link.textContent ?? '';
    expect(display.length).toBeLessThan(longUrl.length); // truncated
    expect(display).toContain('…'); // ellipsis present
    expect(link.getAttribute('href')).toBe(longUrl); // full URL preserved
  });

  it('should render note + excerpt as <dl> peers (no visual hierarchy theater)', async () => {
    setupFixture();
    await loadAndSettle(baseBookmark);

    const note = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-note"]',
    );
    const excerpt = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-excerpt"]',
    );
    expect(note?.textContent).toContain('Why I saved it');
    expect(note?.textContent).toContain('exactly-once semantics');
    expect(excerpt?.textContent).toContain('From the page');
    expect(excerpt?.textContent).toContain('latency in distributed systems');
    // Both rendered inside same <dl> (semantic peers)
    const dl = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-prose"]',
    );
    expect(dl?.tagName.toLowerCase()).toBe('dl');
  });

  it('should hide note row when note is empty', async () => {
    setupFixture();
    await loadAndSettle({ ...baseBookmark, note: '' });
    const note = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-note"]',
    );
    expect(note).toBeFalsy();
  });

  it('should NOT render capture_channel row when value is "manual" (default)', async () => {
    setupFixture();
    await loadAndSettle(baseBookmark);
    const ch = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-capture-channel"]',
    );
    expect(ch).toBeFalsy();
  });

  it('should render capture_channel row when value is non-default', async () => {
    setupFixture();
    await loadAndSettle({ ...baseBookmark, capture_channel: 'rss' });
    const ch = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-capture-channel"]',
    );
    expect(ch?.textContent).toContain('Captured via rss');
  });

  it('should NOT render curated_by row when value is "human" (default)', async () => {
    setupFixture();
    await loadAndSettle(baseBookmark);
    const cb = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-curated-by"]',
    );
    expect(cb).toBeFalsy();
  });

  it('should render curated_by row when value is non-human (delegation signal)', async () => {
    setupFixture();
    await loadAndSettle({ ...baseBookmark, curated_by: 'content-studio' });
    const cb = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-curated-by"]',
    );
    expect(cb?.textContent).toContain('content-studio');
  });

  it('should render feed source attribution when source_feed_entry_id + source_feed_name set', async () => {
    setupFixture();
    await loadAndSettle({
      ...baseBookmark,
      source_feed_entry_id: 'fe-1',
      source_feed_name: 'Hacker News',
      capture_channel: 'rss',
    });
    const feed = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-feed-source"]',
    );
    expect(feed?.textContent).toContain('Captured from RSS: Hacker News');
  });

  it('should expose copy URL button (not slug)', async () => {
    setupFixture();
    await loadAndSettle(baseBookmark);
    const copyBtn = fixture.nativeElement.querySelector(
      '[data-testid="bookmark-copy-url"]',
    );
    expect(copyBtn).toBeTruthy();
    expect(copyBtn?.getAttribute('aria-label')).toBe(
      'Copy bookmark URL to clipboard',
    );
  });

  it('should render error state when fetch fails', async () => {
    setupFixture();
    await loadAndSettle(null);
    const alert = (fixture.nativeElement as HTMLElement).querySelector(
      '[role="alert"]',
    );
    expect(alert?.textContent).toContain('Failed');
  });
});
