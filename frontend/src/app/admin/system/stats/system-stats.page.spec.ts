import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { SystemStatsPageComponent } from './system-stats.page';

// The page reads three live endpoints. Each section owns its state, so
// the specs exercise the per-section degradation contract: a failing
// overview read must not blank the drift table, and vice versa.

const OVERVIEW_URL = '/api/admin/system/stats';
const DRIFT_URL = '/api/admin/system/stats/drift';
const LEARNING_URL = '/api/admin/system/stats/learning';

function overviewPayload(): Record<string, unknown> {
  return {
    contents: {
      total: 120,
      by_status: { published: 90, draft: 20, review: 10 },
      by_type: { til: 80, article: 40 },
      published: 90,
    },
    collected: { total: 800, by_status: { curated: 700, pending: 100 } },
    feeds: { total: 14, enabled: 12 },
    process_runs: {
      crawl: {
        total: 226,
        by_status: { completed: 220, failed: 6 },
      },
      agent_schedule: {
        total: 40,
        by_status: { completed: 40 },
      },
    },
    projects: { total: 11, by_status: { active: 6, paused: 5 } },
    notes: { total: 84, by_type: { 'concept-note': 50, 'solve-note': 34 } },
    activity: {
      total: 4000,
      last_24h: 12,
      last_7d: 90,
      by_source: { human: 60, system: 30 },
    },
    tags: { canonical: 30, aliases: 12, unconfirmed: 4 },
  };
}

function driftPayload(): Record<string, unknown> {
  return {
    period: '30d',
    areas: [
      {
        area: 'engineering',
        active_goals: 2,
        event_count: 50,
        event_percent: 62.5,
        goal_percent: 40,
        drift_percent: 22.5,
      },
      {
        area: 'japanese',
        active_goals: 1,
        event_count: 10,
        event_percent: 12.5,
        goal_percent: 20,
        drift_percent: -7.5,
      },
    ],
  };
}

function learningPayload(): Record<string, unknown> {
  return {
    notes: {
      total: 84,
      last_week: 4,
      last_month: 12,
      by_type: { 'solve-note': 8 },
    },
    activity: { this_week: 9, last_week: 6, trend: 'up' },
    top_tags: [
      { name: 'go', count: 21 },
      { name: 'postgres', count: 9 },
    ],
  };
}

describe('SystemStatsPageComponent', () => {
  let fixture: ComponentFixture<SystemStatsPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [SystemStatsPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(SystemStatsPageComponent);
  });

  afterEach(() => {
    httpMock.verify();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  /** Renders and lets the resource loaders issue their HTTP requests. */
  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function flushAll(): void {
    httpMock
      .expectOne((r) => r.url.endsWith(OVERVIEW_URL))
      .flush({ data: overviewPayload() });
    httpMock
      .expectOne((r) => r.url.endsWith(DRIFT_URL))
      .flush({ data: driftPayload() });
    httpMock
      .expectOne((r) => r.url.endsWith(LEARNING_URL))
      .flush({ data: learningPayload() });
  }

  it('should render tiles, breakdowns, and tables when all reads succeed', async () => {
    await settle();
    flushAll();
    await settle();

    expect(
      el().querySelector('[data-testid="stats-tile-contents"]')?.textContent,
    ).toContain('120');
    expect(
      el().querySelector('[data-testid="stats-tile-feeds"]')?.textContent,
    ).toContain('of 14');

    const byStatus = el().querySelector(
      '[data-testid="stats-breakdown-contents-status"]',
    );
    expect(byStatus?.textContent).toContain('published');
    expect(byStatus?.textContent).toContain('90');

    const runs = el().querySelector(
      '[data-testid="stats-process-runs-row-crawl"]',
    );
    expect(runs?.textContent).toContain('crawl');
    expect(runs?.textContent).toContain('226');
    expect(runs?.textContent).toContain('6');

    const driftRow = el().querySelector(
      '[data-testid="stats-drift-row-engineering"]',
    );
    expect(driftRow?.textContent).toContain('engineering');
    expect(driftRow?.textContent).toContain('22.5%');

    expect(
      el().querySelector('[data-testid="stats-top-tag-go"]')?.textContent,
    ).toContain('21');
    expect(
      el().querySelector('[data-testid="stats-learning-cadence"]')
        ?.textContent,
    ).toContain('9');
  });

  it('should keep drift and learning sections alive when the overview read fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.endsWith(OVERVIEW_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    httpMock
      .expectOne((r) => r.url.endsWith(DRIFT_URL))
      .flush({ data: driftPayload() });
    httpMock
      .expectOne((r) => r.url.endsWith(LEARNING_URL))
      .flush({ data: learningPayload() });
    await settle();

    expect(
      el().querySelector('[data-testid="stats-overview-error"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="stats-drift-row-engineering"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="stats-top-tag-go"]'),
    ).toBeTruthy();
  });

  it('should keep the overview alive when the drift read fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.endsWith(OVERVIEW_URL))
      .flush({ data: overviewPayload() });
    httpMock
      .expectOne((r) => r.url.endsWith(DRIFT_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    httpMock
      .expectOne((r) => r.url.endsWith(LEARNING_URL))
      .flush({ data: learningPayload() });
    await settle();

    expect(
      el().querySelector('[data-testid="stats-drift-error"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="stats-tile-contents"]'),
    ).toBeTruthy();
  });

  it('should re-request only the failed read when its Retry is clicked', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.endsWith(OVERVIEW_URL))
      .flush({ data: overviewPayload() });
    httpMock
      .expectOne((r) => r.url.endsWith(DRIFT_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    httpMock
      .expectOne((r) => r.url.endsWith(LEARNING_URL))
      .flush({ data: learningPayload() });
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="stats-drift-retry"]')
      ?.click();
    await settle();

    httpMock
      .expectOne((r) => r.url.endsWith(DRIFT_URL))
      .flush({ data: driftPayload() });
    await settle();

    expect(el().querySelector('[data-testid="stats-drift-error"]')).toBeNull();
    expect(
      el().querySelector('[data-testid="stats-drift-row-japanese"]'),
    ).toBeTruthy();
  });
});
