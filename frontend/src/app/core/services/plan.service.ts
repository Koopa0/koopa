import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  GoalsOverview,
  GoalDetail,
  GoalProposal,
  GoalProposalResult,
  Milestone,
  ProjectSummary,
  ProjectDetail,
  TaskFilters,
  TaskBacklogItem,
  TaskAdvanceAction,
} from '../models/admin.model';

/** Planning service — goals, projects, task backlog */
@Injectable({ providedIn: 'root' })
export class PlanService {
  private readonly api = inject(ApiService);

  // -----------------------------------------------------------------------
  // Goals
  // -----------------------------------------------------------------------

  getGoalsOverview(): Observable<GoalsOverview> {
    return this.api.getData<GoalsOverview>('/api/admin/plan/goals');
  }

  getGoalDetail(id: string): Observable<GoalDetail> {
    return this.api.getData<GoalDetail>(`/api/admin/plan/goals/${id}`);
  }

  proposeGoal(proposal: GoalProposal): Observable<GoalProposalResult> {
    return this.api.postData<GoalProposalResult>(
      '/api/admin/plan/goals/propose',
      proposal,
    );
  }

  commitGoalProposal(proposalId: string): Observable<GoalDetail> {
    return this.api.postData<GoalDetail>(
      `/api/admin/plan/goals/propose/${proposalId}/commit`,
      {},
    );
  }

  addMilestone(
    goalId: string,
    title: string,
    position: number,
  ): Observable<Milestone> {
    return this.api.postData<Milestone>(
      `/api/admin/plan/goals/${goalId}/milestones`,
      { title, position },
    );
  }

  toggleMilestone(goalId: string, milestoneId: string): Observable<Milestone> {
    return this.api.postData<Milestone>(
      `/api/admin/plan/goals/${goalId}/milestones/${milestoneId}/toggle`,
      {},
    );
  }

  // -----------------------------------------------------------------------
  // Projects
  // -----------------------------------------------------------------------

  getProjectsOverview(
    statusFilter?: string,
  ): Observable<{ projects: ProjectSummary[] }> {
    return this.api.getData<{ projects: ProjectSummary[] }>(
      '/api/admin/plan/projects',
      statusFilter ? { status: statusFilter } : undefined,
    );
  }

  getProjectDetail(id: string): Observable<ProjectDetail> {
    return this.api.getData<ProjectDetail>(`/api/admin/plan/projects/${id}`);
  }

  // -----------------------------------------------------------------------
  // Task Backlog
  // -----------------------------------------------------------------------

  getTaskBacklog(
    filters?: Partial<TaskFilters>,
  ): Observable<{ tasks: TaskBacklogItem[]; meta: { total: number } }> {
    return this.api.getData<{
      tasks: TaskBacklogItem[];
      meta: { total: number };
    }>('/api/admin/plan/tasks', filters as Record<string, string | number>);
  }

  advanceTask(id: string, action: TaskAdvanceAction): Observable<void> {
    return this.api.postVoid(`/api/admin/plan/tasks/${id}/advance`, { action });
  }
}
