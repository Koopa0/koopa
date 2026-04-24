import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  PriorityLevel,
  TodoDetail,
  TodoState,
} from '../models/workbench.model';

/** Row shape returned by the list endpoint. */
export interface TodoRow {
  id: string;
  title: string;
  description: string;
  state: TodoState;
  priority: PriorityLevel | null;
  due_date: string | null;
  project_id: string | null;
  project_title: string | null;
  created_at: string;
  created_by: string;
  updated_at: string;
  recurring: {
    interval: number;
    unit: string;
  } | null;
}

export interface TodoListQuery {
  state?: TodoState;
  project?: string;
  priority?: PriorityLevel;
  due_before?: string;
  sort?: 'due' | 'priority' | 'created_at';
}

export interface TodoCreateRequest {
  title: string;
  state?: 'inbox' | 'todo';
  description?: string;
  project_id?: string;
  priority?: PriorityLevel;
  due_date?: string;
}

export type TodoAdvanceAction =
  | 'clarify'
  | 'start'
  | 'complete'
  | 'defer'
  | 'drop';

export interface TodoUpdateRequest {
  title?: string;
  description?: string;
  project_id?: string | null;
  priority?: PriorityLevel | null;
  due_date?: string | null;
}

/** Todo CRUD + state-machine advance. */
@Injectable({ providedIn: 'root' })
export class TodoService {
  private readonly api = inject(ApiService);

  /** Single-todo detail for the inspector. */
  get(id: string): Observable<TodoDetail> {
    return this.api.getData<TodoDetail>(`/api/admin/commitment/todos/${id}`);
  }

  list(query: TodoListQuery = {}): Observable<TodoRow[]> {
    const params: Record<string, string> = {};
    if (query.state) params['state'] = query.state;
    if (query.project) params['project'] = query.project;
    if (query.priority) params['priority'] = query.priority;
    if (query.due_before) params['due_before'] = query.due_before;
    if (query.sort) params['sort'] = query.sort;
    return this.api.getData<TodoRow[]>('/api/admin/commitment/todos', params);
  }

  create(body: TodoCreateRequest): Observable<TodoRow> {
    return this.api.postData<TodoRow>('/api/admin/commitment/todos', body);
  }

  /** Drive the state machine (inbox → todo → in_progress → done / someday). */
  advance(id: string, action: TodoAdvanceAction): Observable<TodoRow> {
    return this.api.postData<TodoRow>(
      `/api/admin/commitment/todos/${id}/advance`,
      { action },
    );
  }

  /** Field updates only. State transitions go through `advance()`. */
  update(id: string, body: TodoUpdateRequest): Observable<TodoRow> {
    return this.api.putData<TodoRow>(`/api/admin/commitment/todos/${id}`, body);
  }

  remove(id: string): Observable<void> {
    return this.api.delete(`/api/admin/commitment/todos/${id}`);
  }
}
