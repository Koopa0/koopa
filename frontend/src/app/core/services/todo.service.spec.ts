import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { TodoService } from './todo.service';
import type { TodoDetail } from '../models/workbench.model';

const mockTodo: TodoDetail = {
  id: 'todo-1',
  title: 'Fix auth middleware',
  state: 'in_progress',
  description: '',
  due: null,
  energy: 'medium',
  priority: 'high',
  recur_interval: null,
  recur_unit: null,
  completed_at: null,
  project_id: 'proj-1',
  project_title: 'Auth Refactor',
  project_slug: 'auth-refactor',
  assignee: 'human',
  created_by: 'human',
  recent_skip_count_30d: null,
  created_at: '2026-04-15T08:00:00Z',
  updated_at: '2026-04-17T09:00:00Z',
};

describe('TodoService', () => {
  let service: TodoService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(TodoService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch a todo by id', () => {
    service.get('todo-1').subscribe((res) => {
      expect(res.id).toBe('todo-1');
      expect(res.state).toBe('in_progress');
      expect(res.project_title).toBe('Auth Refactor');
    });

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/commitment/todos/todo-1'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockTodo });
  });

  it('should pass list filters when supplied, including per_page', () => {
    service
      .list({ state: 'todo', sort: 'due', per_page: 200 })
      .subscribe((rows) => {
        expect(rows).toHaveLength(0);
      });

    const req = httpMock.expectOne(
      (r) =>
        r.url.endsWith('/api/admin/commitment/todos') &&
        r.params.get('state') === 'todo' &&
        r.params.get('sort') === 'due' &&
        r.params.get('per_page') === '200',
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: [] });
  });

  it('should fetch the recurring buckets', () => {
    service.recurring().subscribe((res) => {
      expect(res.due_today).toHaveLength(1);
      expect(res.due_today[0].recur_interval).toBe(1);
      expect(res.overdue).toHaveLength(0);
    });

    const req = httpMock.expectOne((r) =>
      r.url.endsWith('/api/admin/commitment/todos/recurring'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({
      data: {
        due_today: [
          {
            id: 'recur-1',
            title: 'Review the queue',
            state: 'todo',
            recur_interval: 1,
            recur_unit: 'days',
            created_by: 'human',
            created_at: '2026-06-01T00:00:00Z',
            updated_at: '2026-06-01T00:00:00Z',
          },
        ],
        overdue: [],
      },
    });
  });

  it('should fetch history without q on the completed-since path', () => {
    service.history().subscribe((rows) => {
      expect(rows[0].title).toBe('Shipped the thing');
    });

    const req = httpMock.expectOne(
      (r) =>
        r.url.endsWith('/api/admin/commitment/todos/history') &&
        !r.params.has('q'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({
      data: [
        {
          id: 'hist-1',
          title: 'Shipped the thing',
          completed_at: '2026-06-09T10:00:00Z',
          project_title: 'koopa-core',
        },
      ],
    });
  });

  it('should pass q to history for the search path', () => {
    service.history({ q: 'auth' }).subscribe();

    const req = httpMock.expectOne(
      (r) =>
        r.url.endsWith('/api/admin/commitment/todos/history') &&
        r.params.get('q') === 'auth',
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: [] });
  });

  it('should post the advance action and tolerate the inbox-only drop 204', () => {
    service.advance('todo-1', 'drop').subscribe((res) => {
      expect(res).toBeNull();
    });

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/admin/commitment/todos/todo-1/advance'),
    );
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ action: 'drop' });
    req.flush(null, { status: 204, statusText: 'No Content' });
  });
});
