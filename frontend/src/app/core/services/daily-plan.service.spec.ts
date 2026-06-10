import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { DailyPlanService, type DailyPlan } from './daily-plan.service';

const mockPlan: DailyPlan = {
  date: '2026-06-10',
  total: 2,
  done: 1,
  overdue_count: 0,
  items: [
    {
      id: 'dp-1',
      todo_id: 'todo-1',
      title: 'Fix auth middleware',
      state: 'planned',
      selected_by: 'human',
    },
    {
      id: 'dp-2',
      todo_id: 'todo-2',
      title: 'Write the digest',
      state: 'done',
      completed_at: '2026-06-10T09:00:00Z',
      selected_by: 'planner',
    },
  ],
};

describe('DailyPlanService', () => {
  let service: DailyPlanService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
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
      expect(res.date).toBe('2026-06-10');
      expect(res.items).toHaveLength(2);
      expect(res.items[0].todo_id).toBe('todo-1');
      expect(res.items[1].state).toBe('done');
    });

    const req = httpMock.expectOne(
      (r) =>
        r.url.includes('/api/admin/commitment/daily-plan') &&
        !r.params.has('date'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockPlan });
  });

  it('should pass date param when supplied', () => {
    service.today('2026-06-08').subscribe();

    const req = httpMock.expectOne(
      (r) =>
        r.url.includes('/api/admin/commitment/daily-plan') &&
        r.params.get('date') === '2026-06-08',
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockPlan });
  });

  it('should PUT the full item set on replace', () => {
    const items = [
      { todo_id: 'todo-1', position: 0 },
      { todo_id: 'todo-3', position: 1 },
    ];
    service.replace(items).subscribe((res) => {
      expect(res.total).toBe(2);
      expect(res.items_removed).toHaveLength(0);
    });

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/commitment/daily-plan'),
    );
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ items });
    req.flush({
      data: { date: '2026-06-10', items: [], total: 2, items_removed: [] },
    });
  });
});
