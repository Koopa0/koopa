import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  GoalSummary,
  GoalDetail,
  Milestone,
  ProjectSummary,
  ProjectDetail,
} from '../models/admin.model';
import type { GoalStatus } from '../models';

/**
 * Goal create request. `status` is server-set (always `not_started`).
 * `area_id` is the optional PARA classification (nullable on the server);
 * the rest of the optional fields are sent only when present so the server
 * applies its own defaults.
 */
export interface GoalCreateRequest {
  title: string;
  description: string;
  area_id?: string;
  quarter?: string;
  deadline?: string;
}

/** A PARA area for the goal area selector (GET /commitment/areas). */
export interface Area {
  id: string;
  slug: string;
  name: string;
  sort_order: number;
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
 * PUT /goals/{id} body — partial update of a goal's shaping fields. Every
 * field is optional; the server leaves omitted fields unchanged. `status`
 * is never accepted here (it transitions through {@link updateGoalStatus}).
 * `area_id` set to `null` is not supported by the partial update — omit it
 * to leave the area unchanged.
 */
export interface GoalUpdateRequest {
  title?: string;
  description?: string;
  quarter?: string;
  deadline?: string;
  area_id?: string;
}

/**
 * PUT /goals/{id}/milestones/{mid} body — partial update of a milestone's
 * title / description / target_deadline. Omitted fields stay unchanged.
 */
export interface MilestoneUpdateRequest {
  title?: string;
  description?: string;
  target_deadline?: string;
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

  /**
   * All goals, every status, as a flat array. The unfiltered
   * `GET /commitment/goals` endpoint returns the rich `GoalSummary` row
   * (Goal fields + `area_name` + milestone counts) directly — no `{goals}`
   * envelope. The same shape comes back from the `?status=` path.
   */
  getGoalsOverview(): Observable<GoalSummary[]> {
    return this.api.getData<GoalSummary[]>('/api/admin/commitment/goals');
  }

  /** PARA areas for the goal area selector, ordered by `sort_order`. */
  getAreas(): Observable<Area[]> {
    return this.api.getData<Area[]>('/api/admin/commitment/areas');
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

  /**
   * Partial update of a goal's shaping fields (title / description /
   * quarter / deadline / area_id). Status is excluded — it transitions
   * through {@link updateGoalStatus}. Returns the updated bare goal row;
   * the server responds 404 when the goal does not exist.
   */
  updateGoal(id: string, body: GoalUpdateRequest): Observable<GoalCreated> {
    return this.api.putData<GoalCreated>(
      `/api/admin/commitment/goals/${id}`,
      body,
    );
  }

  /**
   * Partial update of a milestone owned by the goal. The server binds the
   * milestone to the goal in the path, so a cross-goal id is a 404.
   */
  updateMilestone(
    goalId: string,
    milestoneId: string,
    body: MilestoneUpdateRequest,
  ): Observable<Milestone> {
    return this.api.putData<Milestone>(
      `/api/admin/commitment/goals/${goalId}/milestones/${milestoneId}`,
      body,
    );
  }

  /**
   * Delete a milestone owned by the goal. The server responds 204 on
   * success and 404 when the milestone does not exist or belongs to a
   * different goal. Completed milestones are deletable.
   */
  deleteMilestone(goalId: string, milestoneId: string): Observable<void> {
    return this.api.delete(
      `/api/admin/commitment/goals/${goalId}/milestones/${milestoneId}`,
    );
  }
}
