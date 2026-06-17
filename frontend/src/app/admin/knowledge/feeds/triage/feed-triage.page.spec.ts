import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { vi } from 'vitest';

import { FeedTriagePageComponent } from './feed-triage.page';
import type { FeedEntryRow } from '../../../../core/models/feed.model';
import { NotificationService } from '../../../../core/services/notification.service';

// Contract guard for the feed-triage card flow. The fixture mirrors the
// REAL feed-entries wire — entry.Item as encoded by
// internal/feed/entry/handler.go:32-49 (collected.go:32-47): FLAT
// feed_name + feed_id, original_content (omitempty), relevance_score
// always present, NO excerpt / topic_slugs / nested feed object. The page
// previously read a nested { feed: {name} } + excerpt + topic_slugs shape
// that the backend never emits; this pins the flat shape so the drift
// can't recur silently.
const ENTRIES_URL = '/api/admin/knowledge/feed-entries';

/** A full wire entry — the flat fields GET feed-entries returns. */
function entry(overrides: Partial<FeedEntryRow>): FeedEntryRow {
  return {
    id: 'e1',
    source_url: 'https://example.com/post',
    feed_name: 'Example Feed',
    title: 'A Post About Go Value Semantics',
    original_content: 'Copies are not the enemy.',
    relevance_score: 0.82,
    status: 'unread',
    curated_content_id: null,
    collected_at: '2026-06-16T08:00:00Z',
    published_at: '2026-06-15T12:00:00Z',
    user_feedback: null,
    feed_id: 'f1',
    ...overrides,
  };
}

describe('FeedTriagePageComponent', () => {
  let fixture: ComponentFixture<FeedTriagePageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [FeedTriagePageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
    vi.restoreAllMocks();
    TestBed.resetTestingModule();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector(`[data-testid="${id}"]`);
  }

  /** Flush the single entry-list GET; rxResource resolves on a macrotask. */
  async function render(body: FeedEntryRow[]): Promise<void> {
    fixture = TestBed.createComponent(FeedTriagePageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(ENTRIES_URL))
      .flush({ data: body });
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should request unread entries sorted by relevance with the page size', async () => {
    fixture = TestBed.createComponent(FeedTriagePageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();

    const req = httpMock.expectOne((r) => r.url.endsWith(ENTRIES_URL));
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('status')).toBe('unread');
    expect(req.request.params.get('sort')).toBe('relevance');
    expect(req.request.params.get('per_page')).toBe('50');
    // The unwired pre-contraction params must never be sent.
    expect(req.request.params.has('feed_id')).toBe(false);
    expect(req.request.params.has('topic_slug')).toBe(false);
    expect(req.request.params.has('min_relevance')).toBe(false);
    req.flush({ data: [] });
    await fixture.whenStable();
    fixture.detectChanges();
  });

  it('should render the flat wire shape — feed_name, relevance_score and original_content', async () => {
    await render([entry({})]);

    const card = testid('feed-triage-card');
    expect(card).not.toBeNull();
    expect(testid('feed-triage-title')?.textContent).toContain(
      'A Post About Go Value Semantics',
    );
    // feed_name is a flat string on the entry, not entry.feed.name.
    expect(card?.textContent).toContain('Example Feed');
    // relevance_score is always present and rendered to 2 dp.
    expect(testid('feed-triage-relevance')?.textContent).toContain('0.82');
    // The snippet derives from original_content (no excerpt field exists).
    expect(testid('feed-triage-excerpt')?.textContent).toContain(
      'Copies are not the enemy.',
    );
  });

  it('should omit the snippet when original_content is absent', async () => {
    await render([entry({ original_content: undefined })]);

    expect(testid('feed-triage-excerpt')).toBeNull();
    // The card still renders from the rest of the flat shape.
    expect(testid('feed-triage-card')).not.toBeNull();
  });

  it('should advance to the next entry after ignoring the current one', async () => {
    await render([
      entry({ id: 'e1', title: 'First Entry' }),
      entry({ id: 'e2', title: 'Second Entry' }),
    ]);

    expect(testid('feed-triage-title')?.textContent).toContain('First Entry');

    (testid('feed-triage-action-ignore') as HTMLButtonElement).click();
    httpMock
      .expectOne((r) => r.url.endsWith(`${ENTRIES_URL}/e1/ignore`))
      .flush({});
    await fixture.whenStable();
    fixture.detectChanges();

    expect(testid('feed-triage-title')?.textContent).toContain('Second Entry');
  });

  it('should record relevance feedback against the current entry', async () => {
    await render([entry({ id: 'e1' })]);

    (testid('feed-triage-feedback-up') as HTMLButtonElement).click();
    const req = httpMock.expectOne((r) =>
      r.url.endsWith(`${ENTRIES_URL}/e1/feedback`),
    );
    expect(req.request.body).toEqual({ feedback: 'up' });
    req.flush({});
    await fixture.whenStable();
    fixture.detectChanges();

    const notifications = TestBed.inject(NotificationService).notifications();
    expect(notifications.some((n) => n.message === 'Marked relevant.')).toBe(
      true,
    );
  });

  it('should show the inbox-zero state when there are no unread entries', async () => {
    await render([]);

    expect(testid('feed-triage-empty')).not.toBeNull();
    expect(testid('feed-triage-card')).toBeNull();
  });

  it('should surface the error state when the entry read fails', async () => {
    fixture = TestBed.createComponent(FeedTriagePageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(ENTRIES_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Server Error' },
      );
    await fixture.whenStable();
    fixture.detectChanges();

    expect(testid('feed-triage-error')).not.toBeNull();
  });
});
