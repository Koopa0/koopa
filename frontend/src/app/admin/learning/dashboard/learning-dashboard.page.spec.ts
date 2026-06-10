import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { LearningDashboardPageComponent } from './learning-dashboard.page';

// The page reads two live endpoints. Each widget owns its state, so the
// specs exercise the per-widget degradation contract: a failing dashboard
// read must not blank the Streak widget, and vice versa.

const DASHBOARD_URL = '/api/admin/learning/dashboard';
const SUMMARY_URL = '/api/admin/learning/summary';

function dashboardPayload(): Record<string, unknown> {
  return {
    streak_days: 4,
    concepts: {
      count_total: 3,
      counts_by_domain: { leetcode: 2, go: 1 },
      rows: [
        {
          slug: 'two-pointers',
          kind: 'pattern',
          domain: 'leetcode',
          obs_count: 6,
          mastery_value: 0.82,
          mastery_stage: 'solid',
        },
        {
          slug: 'dp-state-design',
          kind: 'skill',
          domain: 'leetcode',
          obs_count: 4,
          mastery_value: 0.25,
          mastery_stage: 'struggling',
        },
        {
          slug: 'goroutine-lifecycle',
          kind: 'principle',
          domain: 'go',
          obs_count: 3,
          mastery_value: 0.55,
          mastery_stage: 'developing',
        },
      ],
    },
    recent_observations: [
      {
        id: 'obs-1',
        signal: 'weakness',
        category: 'state-definition',
        body: 'Struggles to define the DP state before transitions.',
        domain: 'leetcode',
        concept_slug: 'dp-state-design',
        confidence: 'high',
        created_at: '2026-06-09T10:00:00Z',
      },
      {
        id: 'obs-2',
        signal: 'mastery',
        category: 'pattern-recall',
        body: 'Recalled the two-pointer invariant unprompted.',
        domain: 'leetcode',
        concept_slug: 'two-pointers',
        confidence: 'low',
        created_at: '2026-06-08T10:00:00Z',
      },
    ],
  };
}

function emptyDashboardPayload(): Record<string, unknown> {
  return {
    streak_days: 0,
    concepts: { count_total: 0, counts_by_domain: {}, rows: [] },
    recent_observations: [],
  };
}

function summaryPayload(): Record<string, unknown> {
  return {
    streak_days: 4,
    domains: [
      {
        domain: 'leetcode',
        concepts_total: 2,
        concepts_mastered: 1,
        concepts_weak: 1,
        concepts_developing: 0,
      },
    ],
  };
}

describe('LearningDashboardPageComponent', () => {
  let fixture: ComponentFixture<LearningDashboardPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [LearningDashboardPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(LearningDashboardPageComponent);
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

  it('should render all five widgets when both reads succeed', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.includes(DASHBOARD_URL))
      .flush({ data: dashboardPayload() });
    httpMock
      .expectOne((r) => r.url.includes(SUMMARY_URL))
      .flush({ data: summaryPayload() });
    await settle();

    expect(el().querySelector('[data-testid="widget-mastery"]')).toBeTruthy();
    expect(
      el().querySelector('[data-testid="mastery-stage-struggling"]')
        ?.textContent,
    ).toContain('1');
    expect(
      el().querySelector('[data-testid="learning-concept-two-pointers"]'),
    ).toBeTruthy();
    expect(el().textContent).toContain(
      'Recalled the two-pointer invariant unprompted.',
    );
    expect(
      el().querySelector('[data-testid="streak-figures"]')?.textContent,
    ).toContain('4');

    // Weakness widget derives from struggling rows + latest weakness note.
    const weakness = el().querySelector('[data-testid="widget-weakness"]');
    expect(weakness?.textContent).toContain('dp-state-design');
    expect(weakness?.textContent).toContain('25%');
    expect(weakness?.textContent).toContain(
      'Struggles to define the DP state before transitions.',
    );

    // Product-truth guard: live endpoints must never be called "not live".
    expect(el().textContent).not.toContain('not live yet');
  });

  it('should keep the Streak widget alive when the dashboard read fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.includes(DASHBOARD_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    httpMock
      .expectOne((r) => r.url.includes(SUMMARY_URL))
      .flush({ data: summaryPayload() });
    await settle();

    expect(
      el().querySelector('[data-testid="widget-concepts-error"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="widget-mastery-error"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="widget-streak-error"]'),
    ).toBeNull();
    expect(
      el().querySelector('[data-testid="streak-figures"]')?.textContent,
    ).toContain('4');
    expect(el().querySelector('[data-testid="learning-chrome"]')).toBeTruthy();
  });

  it('should keep dashboard widgets alive when the summary read fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.includes(DASHBOARD_URL))
      .flush({ data: dashboardPayload() });
    httpMock
      .expectOne((r) => r.url.includes(SUMMARY_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    await settle();

    expect(
      el().querySelector('[data-testid="widget-streak-error"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="learning-concept-two-pointers"]'),
    ).toBeTruthy();
  });

  it('should re-request the dashboard when Retry is clicked after a failure', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.includes(DASHBOARD_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    httpMock
      .expectOne((r) => r.url.includes(SUMMARY_URL))
      .flush({ data: summaryPayload() });
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="widget-concepts-retry"]')
      ?.click();
    await settle();

    httpMock
      .expectOne((r) => r.url.includes(DASHBOARD_URL))
      .flush({ data: dashboardPayload() });
    await settle();

    expect(
      el().querySelector('[data-testid="widget-concepts-error"]'),
    ).toBeNull();
    expect(
      el().querySelector('[data-testid="learning-concept-two-pointers"]'),
    ).toBeTruthy();
  });

  it('should render per-widget empty states when the dashboard has no data', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.includes(DASHBOARD_URL))
      .flush({ data: emptyDashboardPayload() });
    httpMock
      .expectOne((r) => r.url.includes(SUMMARY_URL))
      .flush({ data: summaryPayload() });
    await settle();

    expect(
      el().querySelector('[data-testid="widget-concepts-empty"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="widget-observations-empty"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="widget-weakness-empty"]'),
    ).toBeTruthy();
  });

  it('should issue a new dashboard request when the confidence filter changes', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.includes(DASHBOARD_URL))
      .flush({ data: dashboardPayload() });
    httpMock
      .expectOne((r) => r.url.includes(SUMMARY_URL))
      .flush({ data: summaryPayload() });
    await settle();

    el()
      .querySelector<HTMLButtonElement>(
        '[data-testid="learning-filter-confidence-all"]',
      )
      ?.click();
    await settle();

    const req = httpMock.expectOne((r) => r.url.includes(DASHBOARD_URL));
    expect(req.request.params.get('confidence_filter')).toBe('all');
    req.flush({ data: dashboardPayload() });
    await settle();
  });
});
