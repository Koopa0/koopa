import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
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
      providers: [provideHttpClient(), provideHttpClientTesting()],
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
});
