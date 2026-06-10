import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  EnergyLevel,
  PriorityLevel,
  TodoDetail,
  TodoState,
} from '../models/workbench.model';

/**
 * Row shape returned by GET /api/admin/commitment/todos. The handler
 * projects a subset of the full item plus the joined project title —
 * `description`, `project_id`, and `completed_at` are not on this wire
 * shape, and `created_by` arrives empty today (the list projection
 * drops it).
 */
export interface TodoRow {
  id: string;
  title: string;
  state: TodoState;
  due?: string | null;
  energy?: EnergyLevel | null;
  priority?: PriorityLevel | null;
  recur_interval?: number | null;
  recur_unit?: string | null;
  created_by?: string;
  created_at: string;
  updated_at: string;
  /** Joined project title; omitted when the todo has no project. */
  project_title?: string;
}

/**
 * Full todo item as serialized by single-item endpoints (create,
 * advance, update) and the recurring buckets.
 */
export interface TodoItem {
  id: string;
  title: string;
  state: TodoState;
  due?: string | null;
  project_id?: string | null;
  completed_at?: string | null;
  energy?: EnergyLevel | null;
  priority?: PriorityLevel | null;
  recur_interval?: number | null;
  recur_unit?: string | null;
  description?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

/** GET /todos/recurring buckets, split by the server day boundary. */
export interface RecurringBuckets {
  due_today: TodoItem[];
  overdue: TodoItem[];
}

/**
 * History row — the common projection of the two history wire shapes
 * (completed-since default path and the ?q= full-text search path).
 */
export interface TodoHistoryEntry {
  id: string;
  title: string;
  completed_at?: string | null;
  project_title: string;
}

export interface TodoListQuery {
  state?: TodoState;
  project?: string;
  priority?: PriorityLevel;
  energy?: EnergyLevel;
  q?: string;
  due_before?: string;
  sort?: 'due' | 'priority' | 'created_at';
  /** Page size, server default 100, max 200. */
  per_page?: number;
}

export interface TodoHistoryQuery {
  q?: string;
  /** YYYY-MM-DD look-back cutoff; server default is 30 days ago. */
  since?: string;
  project?: string;
  /** 1–100, server default 20. */
  limit?: number;
}

export interface TodoCreateRequest {
  title: string;
  state?: 'inbox' | 'todo';
  description?: string;
  project_id?: string;
  priority?: PriorityLevel;
  energy?: EnergyLevel;
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
  project_id?: string;
  priority?: PriorityLevel;
  energy?: EnergyLevel;
  due_date?: string;
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
    if (query.energy) params['energy'] = query.energy;
    if (query.q) params['q'] = query.q;
    if (query.due_before) params['due_before'] = query.due_before;
    if (query.sort) params['sort'] = query.sort;
    if (query.per_page) params['per_page'] = String(query.per_page);
    return this.api.getData<TodoRow[]>('/api/admin/commitment/todos', params);
  }

  /** Recurring todos grouped into due-today / overdue buckets. */
  recurring(): Observable<RecurringBuckets> {
    return this.api.getData<RecurringBuckets>(
      '/api/admin/commitment/todos/recurring',
    );
  }

  /**
   * Completed-todo history. With `q` the server runs full-text search
   * over the completed window; without it, the completed-since list.
   */
  history(query: TodoHistoryQuery = {}): Observable<TodoHistoryEntry[]> {
    const params: Record<string, string> = {};
    if (query.q) params['q'] = query.q;
    if (query.since) params['since'] = query.since;
    if (query.project) params['project'] = query.project;
    if (query.limit) params['limit'] = String(query.limit);
    return this.api.getData<TodoHistoryEntry[]>(
      '/api/admin/commitment/todos/history',
      params,
    );
  }

  create(body: TodoCreateRequest): Observable<TodoItem> {
    return this.api.postData<TodoItem>('/api/admin/commitment/todos', body);
  }

  /**
   * Drive the state machine (inbox → todo → in_progress → done /
   * someday). `drop` is inbox-only and returns 204 with no body.
   */
  advance(id: string, action: TodoAdvanceAction): Observable<TodoItem | null> {
    return this.api.postData<TodoItem | null>(
      `/api/admin/commitment/todos/${id}/advance`,
      { action },
    );
  }

  /** Field updates only. State transitions go through `advance()`. */
  update(id: string, body: TodoUpdateRequest): Observable<TodoItem> {
    return this.api.putData<TodoItem>(
      `/api/admin/commitment/todos/${id}`,
      body,
    );
  }

  remove(id: string): Observable<void> {
    return this.api.delete(`/api/admin/commitment/todos/${id}`);
  }
}
