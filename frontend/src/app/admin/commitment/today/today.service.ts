import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '../../../core/services/api.service';
import type { GoalStatus } from '../../../core/models/api.model';
import type {
  EnergyLevel,
  TodoState,
} from '../../../core/models/workbench.model';

/**
 * Today read-models — bound to GET /api/admin/commitment/today, the HTTP
 * mirror of the agent brief(mode=morning) tool. Field names track the Go
 * wire structs verbatim (internal/today/today.go and the nested
 * todo.PendingDetail / daily.Item / goal.ActiveGoalSummary). Lists are
 * always present ([], never null).
 */

/** A pending todo joined with its project — overdue / today / upcoming. */
export interface PendingDetail {
  id: string;
  title: string;
  state: TodoState;
  due?: string;
  project_title: string;
  project_slug: string;
  energy?: EnergyLevel;
  priority?: string;
  recur_interval?: number;
  recur_unit?: string;
  created_at: string;
  updated_at: string;
}

export type CommittedStatus = 'planned' | 'done' | 'deferred' | 'dropped';

/** A committed daily-plan item — today's plan (daily.Item). */
export interface CommittedItem {
  id: string;
  plan_date: string;
  todo_id: string;
  selected_by: string;
  position: number;
  reason?: string;
  status: CommittedStatus;
  todo_title: string;
  todo_state: string;
  todo_due?: string;
  todo_energy?: string;
  todo_priority?: string;
  project_title: string;
  project_slug: string;
  created_at: string;
  updated_at: string;
}

export interface PlanCompletion {
  planned: number;
  completed: number;
  deferred: number;
}

/** Active goal with milestone rollup (goal.ActiveGoalSummary). */
export interface ActiveGoalSummary {
  id: string;
  title: string;
  description: string;
  status: GoalStatus;
  area_id?: string;
  area_name: string;
  quarter?: string;
  deadline?: string;
  milestone_total: number;
  milestone_done: number;
  created_at: string;
  updated_at: string;
}

export interface RssHighlight {
  title: string;
  url: string;
  feed_name: string;
  created_at: string;
}

/** The full brief(morning) wire shape. */
export interface TodayBrief {
  date: string;
  overdue_todos: PendingDetail[];
  today_todos: PendingDetail[];
  committed_todos: CommittedItem[];
  upcoming_todos: PendingDetail[];
  plan_completion: PlanCompletion;
  active_goals: ActiveGoalSummary[];
  rss_highlights: RssHighlight[];
}

/**
 * Today page composer. A single call to the contracted aggregate endpoint;
 * the backend fans out across the domain stores and degrades per-section,
 * so the front end consumes one envelope rather than orchestrating the
 * morning sections itself.
 */
@Injectable({ providedIn: 'root' })
export class TodayService {
  private readonly api = inject(ApiService);

  today(): Observable<TodayBrief> {
    return this.api.getData<TodayBrief>('/api/admin/commitment/today');
  }
}
