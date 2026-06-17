import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { FeedsListPageComponent } from './feeds-list.page';
import type { FeedRow } from '../../../../core/models/feed.model';

// Contract guard for the feeds-health list. The fixture mirrors the REAL
// GET /api/admin/knowledge/feeds wire — every field the Go Feed struct
// emits (internal/feed/feed.go:122-139, encoded by handler.go:117-130 as
// { data: [...] }). The feed model previously drifted to a nested
// pre-contraction shape (topic_slugs, no disabled_reason) with no spec to
// catch it; this pins the flat shape and the health-derivation rules
// (failing = consecutive_failures > 0; disabled = !enabled).
const FEEDS_URL = '/api/admin/knowledge/feeds';

/** A full wire row — all fields GET /api/admin/knowledge/feeds returns. */
function feed(overrides: Partial<FeedRow>): FeedRow {
  return {
    id: 'f1',
    url: 'https://example.com/feed.xml',
    name: 'Example Feed',
    schedule: 'daily',
    topics: ['go', 'postgres'],
    enabled: true,
    priority: 'normal',
    consecutive_failures: 0,
    last_fetched_at: '2026-06-16T08:00:00Z',
    last_error: '',
    disabled_reason: '',
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

const HEALTHY = feed({
  id: 'f-healthy',
  name: 'Healthy Feed',
  consecutive_failures: 0,
  enabled: true,
});

const FAILING = feed({
  id: 'f-failing',
  name: 'Failing Feed',
  enabled: true,
  consecutive_failures: 3,
  last_error: 'dial tcp: connection refused',
  last_fetched_at: '2026-06-10T08:00:00Z',
});

const DISABLED = feed({
  id: 'f-disabled',
  name: 'Disabled Feed',
  enabled: false,
  consecutive_failures: 5,
  last_error: 'parse: unexpected EOF',
  disabled_reason: '5 consecutive failures',
  last_fetched_at: null,
});

const ROWS: FeedRow[] = [HEALTHY, FAILING, DISABLED];

describe('FeedsListPageComponent', () => {
  let fixture: ComponentFixture<FeedsListPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [FeedsListPageComponent],
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
    TestBed.resetTestingModule();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector(`[data-testid="${id}"]`);
  }

  /** Flush the single list GET; rxResource resolves on a macrotask. */
  async function render(body: FeedRow[]): Promise<void> {
    fixture = TestBed.createComponent(FeedsListPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
    httpMock.expectOne((r) => r.url.endsWith(FEEDS_URL)).flush({ data: body });
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should request the feeds endpoint exactly once as a GET', async () => {
    fixture = TestBed.createComponent(FeedsListPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();

    const req = httpMock.expectOne((r) => r.url.endsWith(FEEDS_URL));
    expect(req.request.method).toBe('GET');
    req.flush({ data: ROWS });
    await fixture.whenStable();
    fixture.detectChanges();
  });

  it('should render a healthy feed (enabled, no failures) as healthy', async () => {
    await render([HEALTHY]);

    const row = testid('feeds-list-row-f-healthy');
    expect(row?.textContent).toContain('Healthy Feed');
    expect(row?.textContent).toContain('healthy');
    // A healthy feed has no error / disabled-reason annotation.
    expect(testid('feeds-list-last-error')).toBeNull();
    expect(testid('feeds-list-disabled-reason')).toBeNull();
  });

  it('should keep a failing feed (consecutive_failures > 0, enabled) under the failing filter', async () => {
    await render(ROWS);

    (testid('feeds-filter-health-failing') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(testid('feeds-count')?.textContent).toContain('1 feed');
    expect(testid('feeds-list-row-f-failing')).not.toBeNull();
    expect(testid('feeds-list-row-f-healthy')).toBeNull();
    expect(testid('feeds-list-row-f-disabled')).toBeNull();
    const row = testid('feeds-list-row-f-failing');
    expect(row?.textContent).toContain('failing');
    // ×N failure-count badge derived from consecutive_failures.
    expect(row?.textContent).toContain('×3');
  });

  it('should keep a disabled feed (enabled=false) under the disabled filter and surface disabled_reason', async () => {
    await render(ROWS);

    (testid('feeds-filter-health-disabled') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(testid('feeds-count')?.textContent).toContain('1 feed');
    expect(testid('feeds-list-row-f-disabled')).not.toBeNull();
    expect(testid('feeds-list-row-f-healthy')).toBeNull();
    expect(testid('feeds-list-row-f-failing')).toBeNull();

    const reason = testid('feeds-list-disabled-reason');
    expect(reason).not.toBeNull();
    expect(reason?.textContent).toContain('5 consecutive failures');
  });

  it('should not show disabled_reason for a feed that is still enabled', async () => {
    // A failing-but-enabled feed has a last_error but no disabled_reason line.
    await render([FAILING]);

    expect(testid('feeds-list-disabled-reason')).toBeNull();
  });

  it('should surface last_error where the failing-feed template shows it', async () => {
    await render([FAILING]);

    const lastError = testid('feeds-list-last-error');
    expect(lastError).not.toBeNull();
    expect(lastError?.textContent).toContain('dial tcp: connection refused');
  });

  it('should render last_fetched_at and a dash when it is null', async () => {
    await render([HEALTHY, DISABLED]);
    (testid('feeds-filter-health-all') as HTMLButtonElement).click();
    fixture.detectChanges();

    // The disabled feed has last_fetched_at: null → em dash fallback.
    const disabledRow = testid('feeds-list-row-f-disabled');
    expect(disabledRow?.textContent).toContain('—');
    // The healthy feed has a timestamp → not the dash for its fetch cell.
    const healthyRow = testid('feeds-list-row-f-healthy');
    expect(healthyRow?.textContent).toContain('Healthy Feed');
  });

  it('should count every feed under the all filter (client-side, no refetch)', async () => {
    await render(ROWS);

    (testid('feeds-filter-health-all') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(testid('feeds-count')?.textContent).toContain('3 feeds');
    httpMock.expectNone((r) => r.url.endsWith(FEEDS_URL));
  });

  it('should keep only the healthy feed under the healthy filter', async () => {
    await render(ROWS);

    (testid('feeds-filter-health-healthy') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(testid('feeds-count')?.textContent).toContain('1 feed');
    expect(testid('feeds-list-row-f-healthy')).not.toBeNull();
    expect(testid('feeds-list-row-f-failing')).toBeNull();
    expect(testid('feeds-list-row-f-disabled')).toBeNull();
  });

  it('should surface the error banner when the list read fails', async () => {
    fixture = TestBed.createComponent(FeedsListPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(FEEDS_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Server Error' },
      );
    await fixture.whenStable();
    fixture.detectChanges();

    expect(testid('feeds-list-error')).not.toBeNull();
  });
});
