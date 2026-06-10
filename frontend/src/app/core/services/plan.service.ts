import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  GoalsOverview,
  GoalDetail,
  Milestone,
  ProjectSummary,
  ProjectDetail,
} from '../models/admin.model';
import type { GoalStatus } from '../models';

/**
 * Goal create request. `status` is server-set (always `not_started`).
 * The server also accepts `area_id`, but no endpoint enumerates areas yet,
 * so the field is not surfaced here. Optional fields are sent only when
 * present so the server applies its own defaults.
 */
export interface GoalCreateRequest {
  title: string;
  description: string;
  quarter?: string;
  deadline?: string;
}

/** POST /goals response — the bare goal row (no milestones/projects). */
export interface GoalCreated {
  id: string;
  title: string;
  description: string;
  status: GoalStatus;
  area_id?: string;
  quarter?: string;
  deadline?: string;
  created_at: string;
  updated_at: string;
}

/**
 * PUT /goals/{id}/status response — a partial projection, NOT the full
 * goal. Callers must re-fetch the detail after a status change.
 */
export interface GoalStatusUpdate {
  title: string;
  status: GoalStatus;
  area_id: string | null;
  updated_at: string;
}

/** Planning service — goals + projects read endpoints (admin REST). */
@Injectable({ providedIn: 'root' })
export class PlanService {
  private readonly api = inject(ApiService);

  getGoalsOverview(): Observable<GoalsOverview> {
    return this.api.getData<GoalsOverview>('/api/admin/commitment/goals');
  }

  /**
   * Create a goal (human-only, adminMid). The server always sets
   * status=not_started; transitions go through {@link updateGoalStatus}.
   * Returns the created goal so the caller can route to its detail page.
   */
  createGoal(body: GoalCreateRequest): Observable<GoalCreated> {
    return this.api.postData<GoalCreated>('/api/admin/commitment/goals', body);
  }

  getGoalDetail(id: string): Observable<GoalDetail> {
    return this.api.getData<GoalDetail>(`/api/admin/commitment/goals/${id}`);
  }

  getProjectsOverview(
    statusFilter?: string,
  ): Observable<{ projects: ProjectSummary[] }> {
    return this.api.getData<{ projects: ProjectSummary[] }>(
      '/api/admin/commitment/projects',
      statusFilter ? { status: statusFilter } : undefined,
    );
  }

  getProjectDetail(id: string): Observable<ProjectDetail> {
    return this.api.getData<ProjectDetail>(
      `/api/admin/commitment/projects/${id}`,
    );
  }

  /**
   * Update goal status. Allowed transitions are enforced server-side;
   * a 400 indicates an illegal state change. The response is partial —
   * re-fetch the detail to refresh the page.
   */
  updateGoalStatus(id: string, status: GoalStatus): Observable<GoalStatusUpdate> {
    return this.api.putData<GoalStatusUpdate>(
      `/api/admin/commitment/goals/${id}/status`,
      { status },
    );
  }

  /**
   * Add a milestone to a goal. The server appends the position and
   * responds 409 when the title conflicts within the goal.
   */
  createMilestone(goalId: string, title: string): Observable<Milestone> {
    return this.api.postData<Milestone>(
      `/api/admin/commitment/goals/${goalId}/milestones`,
      { title },
    );
  }

  /** Flip a milestone's completion (sets or clears completed_at). */
  toggleMilestone(goalId: string, milestoneId: string): Observable<Milestone> {
    return this.api.postData<Milestone>(
      `/api/admin/commitment/goals/${goalId}/milestones/${milestoneId}/toggle`,
      {},
    );
  }
}
