import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
  type TestRequest,
} from '@angular/common/http/testing';

import { AdminNavCountsService } from './admin-nav-counts.service';

// Mocks only the real HTTP boundary. The service fans out to six reads and
// assembles the nav-count envelope. The guarded `counts` computed
// (hasValue() ? value() : EMPTY_ENVELOPE) must never throw a
// ResourceValueError — a failed fan-out blanks the count, it does not take
// down every admin page's sidebar.
const CONTENT_URL = '/api/admin/knowledge/content';
const GOALS_URL = '/api/admin/commitment/goals';
const HYP_URL = '/api/admin/learning/hypotheses';
const HEALTH_URL = '/api/admin/system/health';
const PROPOSALS_COUNT_URL = '/api/admin/commitment/proposals/count';

const EMPTY_ENVELOPE = {
  todos_open: null,
  goals_active: null,
  contents_total: null,
  review_queue: null,
  feeds_active: null,
  hypotheses_unverified: null,
  proposals_pending: null,
};

describe('AdminNavCountsService', () => {
  let service: AdminNavCountsService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    httpMock = TestBed.inject(HttpTestingController);
    service = TestBed.inject(AdminNavCountsService);
    TestBed.tick();
  });

  afterEach(() => {
    httpMock.verify();
  });

  function contentReq(hasReviewStatus: boolean): TestRequest {
    return httpMock.expectOne(
      (r) =>
        r.url.endsWith(CONTENT_URL) &&
        (r.params.get('status') === 'review') === hasReviewStatus,
    );
  }

  function fail(req: TestRequest): void {
    req.flush(
      { error: { code: 'INTERNAL', message: 'boom' } },
      { status: 500, statusText: 'Server Error' },
    );
  }

  it('should assemble the count envelope from the five sources', async () => {
    contentReq(false).flush({
      data: [],
      meta: { total: 12, page: 1, per_page: 1, total_pages: 12 },
    });
    contentReq(true).flush({
      data: [],
      meta: { total: 3, page: 1, per_page: 1, total_pages: 3 },
    });
    httpMock.expectOne((r) => r.url.endsWith(GOALS_URL)).flush({
      data: [
        { id: 'g1', status: 'in_progress' },
        { id: 'g2', status: 'completed' },
      ],
    });
    httpMock
      .expectOne((r) => r.url.endsWith(HYP_URL))
      .flush({ data: [{ id: 'h1' }, { id: 'h2' }] });
    httpMock
      .expectOne((r) => r.url.endsWith(HEALTH_URL))
      .flush({ data: { feeds: { healthy: 7 } } });
    // The count endpoint returns a per-entity breakdown; the service sums
    // goals + areas + projects into the single badge number (here 2+1+1 = 4).
    httpMock
      .expectOne((r) => r.url.endsWith(PROPOSALS_COUNT_URL))
      .flush({
        data: { proposed_goals: 2, proposed_areas: 1, proposed_projects: 1 },
      });
    // rxResource resolves the combined stream on a macrotask.
    await new Promise<void>((r) => setTimeout(r, 0));
    TestBed.tick();

    expect(service.counts()).toMatchObject({
      contents_total: 12,
      review_queue: 3,
      goals_active: 1,
      hypotheses_unverified: 2,
      feeds_active: 7,
      proposals_pending: 4,
    });
  });

  it('should fall back to EMPTY_ENVELOPE without throwing when every source fails', () => {
    fail(contentReq(false));
    fail(contentReq(true));
    fail(httpMock.expectOne((r) => r.url.endsWith(GOALS_URL)));
    fail(httpMock.expectOne((r) => r.url.endsWith(HYP_URL)));
    fail(httpMock.expectOne((r) => r.url.endsWith(HEALTH_URL)));
    fail(httpMock.expectOne((r) => r.url.endsWith(PROPOSALS_COUNT_URL)));
    TestBed.tick();

    // Each source is wrapped in catchError → null, so the guarded counts()
    // resolves to an all-null envelope rather than throwing.
    expect(service.counts()).toEqual(EMPTY_ENVELOPE);
  });
});
