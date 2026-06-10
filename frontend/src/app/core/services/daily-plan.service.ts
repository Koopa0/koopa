import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';

/** Lifecycle state of one planned entry for the day. */
export type DailyPlanEntryState = 'planned' | 'done' | 'deferred' | 'dropped';

/**
 * Wire-level plan entry as returned by GET/PUT
 * /api/admin/commitment/daily-plan (a daily_plan_items row joined with
 * its backing todo).
 */
export interface DailyPlanEntry {
  id: string;
  todo_id: string;
  title: string;
  priority?: string | null;
  state: DailyPlanEntryState;
  reason?: string | null;
  due_date?: string | null;
  completed_at?: string | null;
  selected_by: string;
}

/** Response shape of GET /api/admin/commitment/daily-plan. */
export interface DailyPlan {
  date: string;
  items: DailyPlanEntry[];
  total: number;
  done: number;
  overdue_count: number;
}

/** One entry in the PUT body; position defaults to the item's index. */
export interface DailyPlanWriteItem {
  todo_id: string;
  position?: number;
}

/** A todo displaced from a prior plan by a PUT replace. */
export interface DailyPlanRemovedItem {
  id: string;
  todo_id: string;
  todo_title: string;
}

/** Response shape of PUT /api/admin/commitment/daily-plan. */
export interface DailyPlanWriteResult {
  date: string;
  items: DailyPlanEntry[];
  total: number;
  items_removed: DailyPlanRemovedItem[];
}

/**
 * Daily plan — the per-date committed todo set. The PUT is an atomic
 * replace of the date's planned rows: callers send the FULL desired
 * set (the server rejects empty item lists and inbox-state todos).
 */
@Injectable({ providedIn: 'root' })
export class DailyPlanService {
  private readonly api = inject(ApiService);

  /** Today's plan. Optional `date` (YYYY-MM-DD) overrides server today. */
  today(date?: string): Observable<DailyPlan> {
    const params = date ? { date } : undefined;
    return this.api.getData<DailyPlan>(
      '/api/admin/commitment/daily-plan',
      params,
    );
  }

  /**
   * Atomically replace the date's planned entries with `items`.
   * Append = current planned entries in order plus the new todo.
   */
  replace(
    items: DailyPlanWriteItem[],
    date?: string,
  ): Observable<DailyPlanWriteResult> {
    const body: { items: DailyPlanWriteItem[]; date?: string } = { items };
    if (date) body.date = date;
    return this.api.putData<DailyPlanWriteResult>(
      '/api/admin/commitment/daily-plan',
      body,
    );
  }
}
