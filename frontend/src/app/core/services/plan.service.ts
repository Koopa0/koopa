import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  GoalsOverview,
  GoalDetail,
  ProjectSummary,
  ProjectDetail,
} from '../models/admin.model';

/** Planning service — goals + projects read endpoints (admin REST). */
@Injectable({ providedIn: 'root' })
export class PlanService {
  private readonly api = inject(ApiService);

  getGoalsOverview(): Observable<GoalsOverview> {
    return this.api.getData<GoalsOverview>('/api/admin/commitment/goals');
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
   * a 400 indicates an illegal state change.
   */
  updateGoalStatus(id: string, status: string): Observable<GoalDetail> {
    return this.api.putData<GoalDetail>(
      `/api/admin/commitment/goals/${id}/status`,
      {
        status,
      },
    );
  }
}
