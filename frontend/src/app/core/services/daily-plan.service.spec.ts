import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { DailyPlanService } from './daily-plan.service';
import type { DailyPlanResponse } from '../models/workbench.model';

const mockResponse: DailyPlanResponse = {
  date: '2026-04-17',
  state: 'ok',
  total: 3,
  done: 1,
  overdue_count: 0,
  items: [
    {
      id: 'dp-1',
      todo_id: 'todo-1',
      todo_title: 'Fix auth middleware',
      todo_state: 'in_progress',
      todo_assignee: 'human',
      status: 'planned',
      position: 0,
      selected_by: 'hq',
    },
  ],
};

describe('DailyPlanService', () => {
  let service: DailyPlanService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(DailyPlanService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it("should fetch today's plan when no date is given", () => {
    service.today().subscribe((res) => {
      expect(res.date).toBe('2026-04-17');
      expect(res.items).toHaveLength(1);
      expect(res.state).toBe('ok');
    });

    const req = httpMock.expectOne(
      (r) => r.url.includes('/api/admin/commitment/daily-plan') && !r.params.has('date'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockResponse });
  });

  it('should pass date param when supplied', () => {
    service.today('2026-04-15').subscribe();

    const req = httpMock.expectOne(
      (r) =>
        r.url.includes('/api/admin/commitment/daily-plan') &&
        r.params.get('date') === '2026-04-15',
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockResponse });
  });

  it('should surface warn state when overdue items exist', () => {
    service.today().subscribe((res) => {
      expect(res.state).toBe('warn');
      expect(res.reason).toBe('1 overdue from yesterday');
    });

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/commitment/daily-plan'),
    );
    req.flush({
      data: {
        ...mockResponse,
        state: 'warn',
        reason: '1 overdue from yesterday',
        overdue_count: 1,
      },
    });
  });
});
