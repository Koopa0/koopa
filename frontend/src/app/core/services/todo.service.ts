import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  EnergyLevel,
  PriorityLevel,
  TodoState,
} from '../models/workbench.model';

/**
 * Row shape returned by GET /api/admin/commitment/todos. The handler
 * projects a subset of the full item plus the joined project title and
 * the capture's free-text `description` — `project_id` and `completed_at`
 * are not on this wire shape. `created_by` carries the capture's origin:
 * `human` for an admin capture, the agent name (e.g. `hermes`) for an MCP
 * capture.
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
  /**
   * Weekday-mode recurrence mask. A row is recurring when EITHER recur_interval
   * (interval mode) OR recur_weekdays (weekday mode) is set; treating only
   * recur_interval as recurring let weekday routines leak into the Pending tab
   * with no recurrence badge.
   */
  recur_weekdays?: number | null;
  /** Capture free-text detail (e.g. hermes context); omitted when empty. */
  description?: string;
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
  /** Weekday-mode recurrence mask (Mon=bit0..Sun=bit6); see TodoRow. */
  recur_weekdays?: number | null;
  description?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

/** GET /todos/recurring: occurrences due today (compute-on-read). */
export interface RecurringBuckets {
  due_today: TodoItem[];
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
  /**
   * Single state or a set of states. A list serializes to the
   * comma-separated `state=` the server splits and validates per element
   * (e.g. `inbox,todo,in_progress,someday` for the backlog), so a long done
   * history can't push live rows past the per_page cap.
   */
  state?: TodoState | TodoState[];
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
  | 'activate'
  | 'drop';

export interface TodoUpdateRequest {
  title?: string;
  description?: string;
  project_id?: string;
  priority?: PriorityLevel;
  energy?: EnergyLevel;
  due_date?: string;
}

export type TodoWeekday = 'mon' | 'tue' | 'wed' | 'thu' | 'fri' | 'sat' | 'sun';
export type RecurUnit = 'days' | 'weeks' | 'months' | 'years';

/**
 * Set/clear a todo's recurrence (admin, owner). Exactly one of weekdays,
 * interval+unit, or clear. Mirrors the MCP set_todo_recurrence shape; the
 * server validates the mutual exclusivity.
 */
export interface RecurrenceRequest {
  weekdays?: TodoWeekday[];
  interval?: number;
  unit?: RecurUnit;
  clear?: boolean;
}

/** Todo CRUD + state-machine advance. */
@Injectable({ providedIn: 'root' })
export class TodoService {
  private readonly api = inject(ApiService);

  list(query: TodoListQuery = {}): Observable<TodoRow[]> {
    const params: Record<string, string> = {};
    if (query.state) {
      params['state'] = Array.isArray(query.state)
        ? query.state.join(',')
        : query.state;
    }
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
   * someday; someday → todo via `activate`). `drop` is inbox-only and
   * returns 204 with no body.
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

  /**
   * Set or clear a todo's recurrence (weekday-mode, interval-mode, or clear).
   * The owner-side counterpart of the MCP set_todo_recurrence; turns a one-off
   * into a routine that resurfaces on its schedule (compute-on-read).
   */
  setRecurrence(id: string, body: RecurrenceRequest): Observable<TodoItem> {
    return this.api.putData<TodoItem>(
      `/api/admin/commitment/todos/${id}/recurrence`,
      body,
    );
  }

  remove(id: string): Observable<void> {
    return this.api.delete(`/api/admin/commitment/todos/${id}`);
  }
}
