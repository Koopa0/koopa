import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { SystemHealthPageComponent } from './system-health.page';

const HEALTH_URL = '/api/admin/system/health';

function healthPayload(): Record<string, unknown> {
  return {
    feeds: {
      total: 14,
      healthy: 12,
      failing: 2,
      failing_feeds: [
        {
          name: 'Go Blog',
          error: 'dial tcp: i/o timeout',
          since: '2026-06-09T08:00:00Z',
        },
        { name: 'HN Daily', error: 'http 503' },
      ],
    },
    pipelines: {
      recent_runs: 226,
      failed: 0,
      last_run_at: '2026-06-10T06:00:00Z',
    },
    database: {
      contents_count: 120,
      todos_count: 45,
    },
  };
}

function allHealthyPayload(): Record<string, unknown> {
  return {
    feeds: { total: 14, healthy: 14, failing: 0, failing_feeds: [] },
    pipelines: { recent_runs: 226, failed: 0, last_run_at: null },
    database: {
      contents_count: 0,
      todos_count: 0,
    },
  };
}

describe('SystemHealthPageComponent', () => {
  let fixture: ComponentFixture<SystemHealthPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [SystemHealthPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(SystemHealthPageComponent);
  });

  afterEach(() => {
    httpMock.verify();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  /** Renders and lets the resource loader issue its HTTP request. */
  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  it('should render all three panels when the read succeeds', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.endsWith(HEALTH_URL))
      .flush({ data: healthPayload() });
    await settle();

    expect(el().querySelector('[data-testid="health-feeds"]')).toBeTruthy();
    expect(
      el().querySelector('[data-testid="health-pipelines"]'),
    ).toBeTruthy();
    expect(el().querySelector('[data-testid="health-database"]')).toBeTruthy();

    expect(
      el().querySelector('[data-testid="health-tile-feeds-healthy"]')
        ?.textContent,
    ).toContain('12');
    expect(
      el().querySelector('[data-testid="health-tile-pipelines-runs"]')
        ?.textContent,
    ).toContain('226');
  });

  it('should render exactly the contents/todos database tiles', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.endsWith(HEALTH_URL))
      .flush({ data: healthPayload() });
    await settle();

    // Pin the database panel's tile set so a dropped or re-added tile
    // (e.g. the removed learning attempts/sessions/concepts tiles) fails
    // here instead of rendering an undefined value. Scope the query to the
    // database panel so feed/pipeline tiles don't bleed into the assertion.
    const panel = el().querySelector('[data-testid="health-database"]');
    expect(panel).toBeTruthy();
    const tileIds = Array.from(
      panel!.querySelectorAll('[data-testid^="health-tile-"]'),
    ).map((node) => node.getAttribute('data-testid'));
    expect(tileIds).toEqual([
      'health-tile-db-contents',
      'health-tile-db-todos',
    ]);
    expect(
      el().querySelector('[data-testid="health-tile-db-contents"]')
        ?.textContent,
    ).toContain('120');
    expect(
      el().querySelector('[data-testid="health-tile-db-todos"]')?.textContent,
    ).toContain('45');
  });

  it('should list failing feeds with their error text when feeds fail', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.endsWith(HEALTH_URL))
      .flush({ data: healthPayload() });
    await settle();

    const failing = el().querySelector('[data-testid="health-failing-feeds"]');
    expect(failing).toBeTruthy();
    expect(failing?.textContent).toContain('Go Blog');
    expect(failing?.textContent).toContain('dial tcp: i/o timeout');
    expect(failing?.textContent).toContain('failing since');
    expect(failing?.textContent).toContain('HN Daily');
    expect(failing?.textContent).toContain('http 503');
    expect(
      el().querySelector('[data-testid="health-feeds-badge"]')?.textContent,
    ).toContain('2 failing');
  });

  it('should show healthy badges and no failing list when everything passes', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.endsWith(HEALTH_URL))
      .flush({ data: allHealthyPayload() });
    await settle();

    expect(
      el().querySelector('[data-testid="health-feeds-badge"]')?.textContent,
    ).toContain('healthy');
    expect(
      el().querySelector('[data-testid="health-pipelines-badge"]')
        ?.textContent,
    ).toContain('passing');
    expect(
      el().querySelector('[data-testid="health-failing-feeds"]'),
    ).toBeNull();
    expect(
      el().querySelector('[data-testid="health-feeds-all-healthy"]'),
    ).toBeTruthy();
    expect(
      el().querySelector('[data-testid="health-pipelines-last-run"]')
        ?.textContent,
    ).toContain('never');
  });

  it('should show the error state and re-request on retry when the read fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.endsWith(HEALTH_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    await settle();

    expect(el().querySelector('[data-testid="health-error"]')).toBeTruthy();
    expect(el().querySelector('[data-testid="health-feeds"]')).toBeNull();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="health-retry"]')
      ?.click();
    await settle();

    httpMock
      .expectOne((r) => r.url.endsWith(HEALTH_URL))
      .flush({ data: healthPayload() });
    await settle();

    expect(el().querySelector('[data-testid="health-error"]')).toBeNull();
    expect(el().querySelector('[data-testid="health-feeds"]')).toBeTruthy();
  });
});
