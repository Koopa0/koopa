import { Injectable, inject } from '@angular/core';
import { Observable, of } from 'rxjs';
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

/** 規劃服務 — 目標、專案、任務待辦 */
@Injectable({ providedIn: 'root' })
export class PlanService {
  private readonly api = inject(ApiService);

  // -----------------------------------------------------------------------
  // Goals
  // -----------------------------------------------------------------------

  getGoalsOverview(): Observable<GoalsOverview> {
    // TODO: return this.api.getData<GoalsOverview>('/api/admin/plan/goals');
    return of(MOCK_GOALS_OVERVIEW);
  }

  getGoalDetail(id: string): Observable<GoalDetail> {
    // TODO: return this.api.getData<GoalDetail>(`/api/admin/plan/goals/${id}`);
    const detail = MOCK_GOAL_DETAILS[id];
    return of(detail ?? MOCK_GOAL_DETAILS['goal-001']);
  }

  proposeGoal(proposal: GoalProposal): Observable<GoalProposalResult> {
    // TODO: return this.api.postData<GoalProposalResult>('/api/admin/plan/goals/propose', proposal);
    return of({
      proposal_id: `proposal-${Date.now()}`,
      preview: {
        title: proposal.title,
        area_name: 'Backend',
        deadline: proposal.deadline ?? null,
        existing_goals_in_area: 2,
        quarter: proposal.quarter ?? '2026-Q2',
      },
    });
  }

  commitGoalProposal(_proposalId: string): Observable<GoalDetail> {
    // TODO: return this.api.postData<GoalDetail>(`/api/admin/plan/goals/propose/${proposalId}/commit`, {});
    return of(MOCK_GOAL_DETAILS['goal-001']);
  }

  addMilestone(
    goalId: string,
    title: string,
    position: number,
  ): Observable<Milestone> {
    return of({
      id: `ms-${Date.now()}`,
      title,
      position,
      completed: false,
      completed_at: null,
      projects: [],
    });
  }

  toggleMilestone(goalId: string, milestoneId: string): Observable<Milestone> {
    return of({
      id: milestoneId,
      title: 'Admin UI redesign',
      position: 1,
      completed: true,
      completed_at: new Date().toISOString(),
      projects: [],
    });
  }

  // -----------------------------------------------------------------------
  // Projects
  // -----------------------------------------------------------------------

  getProjectsOverview(
    statusFilter?: string,
  ): Observable<{ projects: ProjectSummary[] }> {
    const filtered = statusFilter
      ? MOCK_PROJECTS.filter((p) => p.status === statusFilter)
      : MOCK_PROJECTS;
    return of({ projects: filtered });
  }

  getProjectDetail(_id: string): Observable<ProjectDetail> {
    // TODO: return this.api.getData<ProjectDetail>(`/api/admin/plan/projects/${id}`);
    return of(MOCK_PROJECT_DETAIL);
  }

  // -----------------------------------------------------------------------
  // Task Backlog
  // -----------------------------------------------------------------------

  getTaskBacklog(
    filters?: Partial<TaskFilters>,
  ): Observable<{ tasks: TaskBacklogItem[]; meta: { total: number } }> {
    let tasks = [...MOCK_TASK_BACKLOG];
    if (filters?.status) {
      tasks = tasks.filter((t) => t.status === filters.status);
    }
    return of({ tasks, meta: { total: tasks.length } });
  }

  advanceTask(_id: string, _action: TaskAdvanceAction): Observable<void> {
    // TODO: return this.api.postVoid(`/api/admin/plan/tasks/${id}/advance`, { action });
    return of(undefined);
  }
}

// ---------------------------------------------------------------------------
// Mock Data — 欄位嚴格對齊 admin.model.ts
// ---------------------------------------------------------------------------

const MOCK_GOALS_OVERVIEW: GoalsOverview = {
  by_area: [
    {
      area_id: 'area-backend',
      area_name: 'Backend',
      area_slug: 'backend',
      goals: [
        {
          id: 'goal-001',
          title: 'Ship koopa0.dev v1 public launch',
          status: 'in-progress',
          deadline: '2026-06-30',
          days_remaining: 83,
          milestones_total: 4,
          milestones_done: 2,
          next_milestone_title: 'Admin UI redesign',
          projects_count: 2,
          quarter: '2026-Q2',
        },
      ],
    },
    {
      area_id: 'area-learning',
      area_name: 'Learning',
      area_slug: 'learning',
      goals: [
        {
          id: 'goal-002',
          title: 'Publish 12 technical articles by Q2',
          status: 'in-progress',
          deadline: '2026-06-30',
          days_remaining: 83,
          milestones_total: 3,
          milestones_done: 1,
          next_milestone_title: 'Articles 5-8 published',
          projects_count: 1,
          quarter: '2026-Q2',
        },
        {
          id: 'goal-004',
          title: 'Complete DDIA reading notes',
          status: 'not-started',
          deadline: '2026-09-30',
          days_remaining: 175,
          milestones_total: 12,
          milestones_done: 0,
          next_milestone_title: 'Chapter 1-2 notes',
          projects_count: 0,
          quarter: '2026-Q3',
        },
      ],
    },
    {
      area_id: 'area-career',
      area_name: 'Career',
      area_slug: 'career',
      goals: [
        {
          id: 'goal-003',
          title: 'Apply for Google Developer Expert',
          status: 'in-progress',
          deadline: '2026-05-25',
          days_remaining: 47,
          milestones_total: 4,
          milestones_done: 2,
          next_milestone_title: 'Community contribution portfolio ready',
          projects_count: 0,
          quarter: '2026-Q2',
        },
      ],
    },
  ],
};

const MOCK_GOAL_DETAILS: Record<string, GoalDetail> = {
  'goal-001': {
    id: 'goal-001',
    title: 'Ship koopa0.dev v1 public launch',
    description:
      'Complete the personal knowledge engine platform: Go API, Angular frontend, AI pipeline, and deploy to production.',
    status: 'in-progress',
    area_id: 'area-backend',
    area_name: 'Backend',
    deadline: '2026-06-30',
    quarter: '2026-Q2',
    created_at: '2026-01-15T10:00:00+08:00',
    health: 'on-track',
    milestones: [
      {
        id: 'ms-001',
        title: 'Core API endpoints (content, topics, projects)',
        position: 1,
        completed: true,
        completed_at: '2026-03-01T14:00:00+08:00',
      },
      {
        id: 'ms-002',
        title: 'Admin UI redesign',
        position: 2,
        completed: false,
        completed_at: null,
      },
      {
        id: 'ms-003',
        title: 'AI pipeline (Genkit flows) for content processing',
        position: 3,
        completed: true,
        completed_at: '2026-03-20T16:00:00+08:00',
      },
      {
        id: 'ms-004',
        title: 'Production deploy with monitoring',
        position: 4,
        completed: false,
        completed_at: null,
      },
    ],
    projects: [
      {
        id: 'proj-001',
        title: 'koopa0.dev Backend',
        status: 'in-progress',
        task_progress: { total: 22, done: 14 },
      },
      {
        id: 'proj-002',
        title: 'koopa0.dev Frontend',
        status: 'in-progress',
        task_progress: { total: 18, done: 7 },
      },
    ],
    recent_activity: [
      {
        type: 'task_completed',
        title: 'Set up pgvector extension',
        timestamp: '2026-04-07T16:30:00+08:00',
      },
      {
        type: 'commit',
        title: 'feat: add admin sidebar redesign',
        timestamp: '2026-04-08T10:00:00+08:00',
      },
    ],
  },
};

const MOCK_PROJECTS: ProjectSummary[] = [
  {
    id: 'proj-001',
    title: 'koopa0.dev Backend',
    slug: 'koopa0-dev-backend',
    area: 'backend',
    status: 'in-progress',
    goal_breadcrumb: {
      goal_id: 'goal-001',
      goal_title: 'Ship koopa0.dev v1',
    },
    task_progress: { total: 22, done: 14 },
    staleness_days: 0,
    last_activity_at: '2026-04-08T01:30:00+08:00',
  },
  {
    id: 'proj-002',
    title: 'koopa0.dev Frontend',
    slug: 'koopa0-dev-frontend',
    area: 'frontend',
    status: 'in-progress',
    goal_breadcrumb: {
      goal_id: 'goal-001',
      goal_title: 'Ship koopa0.dev v1',
    },
    task_progress: { total: 18, done: 7 },
    staleness_days: 0,
    last_activity_at: '2026-04-08T02:15:00+08:00',
  },
  {
    id: 'proj-003',
    title: 'Go Concurrency Patterns Article',
    slug: 'go-concurrency-article',
    area: 'learning',
    status: 'in-progress',
    goal_breadcrumb: {
      goal_id: 'goal-002',
      goal_title: 'Publish 12 articles',
    },
    task_progress: { total: 5, done: 3 },
    staleness_days: 2,
    last_activity_at: '2026-04-06T20:00:00+08:00',
  },
  {
    id: 'proj-005',
    title: 'Obsidian Plugin: Auto-Frontmatter',
    slug: 'obsidian-auto-frontmatter',
    area: 'backend',
    status: 'on-hold',
    goal_breadcrumb: null,
    task_progress: { total: 8, done: 2 },
    staleness_days: 19,
    last_activity_at: '2026-03-20T10:00:00+08:00',
  },
];

const MOCK_PROJECT_DETAIL: ProjectDetail = {
  id: 'proj-002',
  title: 'koopa0.dev Frontend',
  slug: 'koopa0-dev-frontend',
  description:
    'Angular 21 SSR frontend for the personal knowledge engine platform.',
  problem: 'Current admin is CMS-style, not workflow-first.',
  solution: 'Redesign as temporal operating console.',
  architecture: 'Angular 21 + Tailwind v4 + NgRx Signals',
  status: 'in-progress',
  area: 'frontend',
  goal_breadcrumb: {
    goal_id: 'goal-001',
    goal_title: 'Ship koopa0.dev v1',
  },
  tasks_by_status: {
    in_progress: [
      {
        id: 'task-101',
        title: 'Implement admin sidebar navigation',
        priority: 'high',
        energy: 'high',
        due: '2026-04-09',
        is_in_today_plan: true,
      },
    ],
    todo: [
      {
        id: 'task-105',
        title: 'Build Today page with My Day widget',
        priority: 'high',
        energy: 'high',
        due: '2026-04-11',
        is_in_today_plan: false,
      },
      {
        id: 'task-107',
        title: 'Create inbox capture quick-entry component',
        priority: 'medium',
        energy: 'medium',
        due: null,
        is_in_today_plan: false,
      },
    ],
    done: [
      {
        id: 'task-100',
        title: 'Set up admin layout with sidebar',
        priority: 'high',
        energy: 'high',
        due: null,
        is_in_today_plan: false,
      },
    ],
    someday: [],
  },
  recent_activity: [
    {
      type: 'commit',
      title: 'feat: restructure admin routes',
      timestamp: '2026-04-08T10:00:00+08:00',
    },
  ],
  related_content: [
    {
      id: 'content-001',
      title: 'Admin Redesign Build Log',
      type: 'build-log',
      slug: 'admin-redesign-build-log',
    },
  ],
};

const MOCK_TASK_BACKLOG: TaskBacklogItem[] = [
  {
    id: 'task-101',
    title: 'Implement admin sidebar navigation',
    status: 'in-progress',
    area: 'frontend',
    priority: 'high',
    energy: 'high',
    due: '2026-04-09',
    project_title: 'koopa0.dev Frontend',
    is_in_today_plan: true,
  },
  {
    id: 'task-102',
    title: 'Write pgx integration tests for content store',
    status: 'todo',
    area: 'backend',
    priority: 'high',
    energy: 'high',
    due: '2026-04-10',
    project_title: 'koopa0.dev Backend',
    is_in_today_plan: true,
  },
  {
    id: 'task-103',
    title: 'Review RSS pipeline error handling',
    status: 'in-progress',
    area: 'backend',
    priority: 'medium',
    energy: 'medium',
    due: '2026-04-08',
    project_title: 'koopa0.dev Backend',
    is_in_today_plan: false,
  },
  {
    id: 'task-104',
    title: 'Draft Go error handling article outline',
    status: 'todo',
    area: 'learning',
    priority: 'medium',
    energy: 'medium',
    due: '2026-04-12',
    project_title: 'Go Concurrency Patterns Article',
    is_in_today_plan: false,
  },
  {
    id: 'task-105',
    title: 'Build Today page with My Day widget',
    status: 'todo',
    area: 'frontend',
    priority: 'high',
    energy: 'high',
    due: '2026-04-11',
    project_title: 'koopa0.dev Frontend',
    is_in_today_plan: false,
  },
  {
    id: 'task-106',
    title: 'Solve LeetCode #752 Open the Lock (BFS)',
    status: 'todo',
    area: 'learning',
    priority: 'low',
    energy: 'medium',
    due: null,
    project_title: 'LeetCode Daily Practice',
    is_in_today_plan: false,
  },
  {
    id: 'task-090',
    title: 'Migrate Obsidian sync to NATS JetStream',
    status: 'todo',
    area: 'backend',
    priority: 'high',
    energy: 'high',
    due: '2026-04-05',
    project_title: 'koopa0.dev Backend',
    is_in_today_plan: false,
  },
];
