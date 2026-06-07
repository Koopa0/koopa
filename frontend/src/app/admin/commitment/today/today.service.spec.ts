import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { firstValueFrom } from 'rxjs';

import { TodayService, type TodayBrief } from './today.service';

function emptyBrief(): TodayBrief {
  return {
    date: '2026-06-07',
    overdue_todos: [],
    today_todos: [],
    committed_todos: [],
    upcoming_todos: [],
    plan_completion: { planned: 0, completed: 0, deferred: 0 },
    active_goals: [],
    unverified_hypotheses: [],
    rss_highlights: [],
  };
}

describe('TodayService', () => {
  let service: TodayService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(TodayService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('should GET the brief(morning) aggregate from the contracted endpoint', async () => {
    const brief = emptyBrief();
    const promise = firstValueFrom(service.today());

    const req = httpMock.expectOne((r) =>
      r.url.endsWith('/api/admin/commitment/today'),
    );
    expect(req.request.method).toBe('GET');
    req.flush(brief);

    expect(await promise).toEqual(brief);
  });

  it('should preserve omitted active_session when no session is open', async () => {
    const promise = firstValueFrom(service.today());
    const req = httpMock.expectOne((r) =>
      r.url.endsWith('/api/admin/commitment/today'),
    );
    req.flush(emptyBrief());

    const result = await promise;
    expect(result.active_session).toBeUndefined();
  });
});
