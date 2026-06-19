import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';

import { ProposalService } from './proposal.service';

// Mocks only the real HTTP boundary, asserting the outgoing request (method +
// URL + body) and the mapped response — the observable contract.
const COUNT_URL = '/api/admin/commitment/proposals/count';
const projectActivate = (id: string) =>
  `/api/admin/commitment/projects/${id}/activate`;
const projectProposed = (id: string) =>
  `/api/admin/commitment/projects/${id}/proposed`;

describe('ProposalService', () => {
  let service: ProposalService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    httpMock = TestBed.inject(HttpTestingController);
    service = TestBed.inject(ProposalService);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should sum the goal/area/project breakdown into one pending count', () => {
    let total: number | undefined;
    service.count().subscribe((n) => (total = n));

    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(COUNT_URL))
      .flush({
        data: { proposed_goals: 2, proposed_areas: 1, proposed_projects: 3 },
      });

    expect(total).toBe(6);
  });

  it('should POST an empty body to the project activate endpoint', () => {
    service.activateProject('pr-1').subscribe();

    const req = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(projectActivate('pr-1')),
    );
    expect(req.request.body).toEqual({});
    req.flush({});
  });

  it('should DELETE the proposed project on reject', () => {
    service.rejectProject('pr-1').subscribe();

    httpMock
      .expectOne(
        (r) => r.method === 'DELETE' && r.url.endsWith(projectProposed('pr-1')),
      )
      .flush(null, { status: 204, statusText: 'No Content' });
  });
});
