/** Admin workbench models. */

import type { ContentType, GoalStatus } from './api.model';

// === Plan — Goals ===

/**
 * GET /api/admin/commitment/goals — a flat array of goal rows, every
 * status (or one status with `?status=`). Mirrors the Go
 * `goal.ActiveGoalSummary` (the `Goal` struct fields + `area_name` +
 * milestone counts), which both the filtered and unfiltered paths return
 * through `GoalsByOptionalStatus`. `area_name` is `''` when the goal has
 * no area; `milestone_total` / `milestone_done` are singular (the Go JSON
 * tags). The admin list renders milestone progress straight from this row.
 */
export interface GoalSummary {
  id: string;
  title: string;
  description: string;
  status: GoalStatus;
  area_id?: string;
  quarter?: string;
  deadline?: string | null;
  created_at: string;
  updated_at: string;
  area_name: string;
  milestone_total: number;
  milestone_done: number;
}

/**
 * GET /api/admin/commitment/goals/{id} — milestones and projects are
 * siblings, not parent-child. Mirrors goalDetailResponse
 * (internal/goal/handler.go); area/deadline/quarter are omitted when unset.
 */
export interface GoalDetail {
  id: string;
  title: string;
  description: string;
  status: GoalStatus;
  area_id?: string;
  area_name?: string;
  deadline?: string | null;
  quarter?: string | null;
  milestones: Milestone[];
  projects: GoalProject[];
  recent_activity: ActivityItem[];
  created_at: string;
  updated_at: string;
}

/** Milestone — binary completion (completed_at absent = not completed). */
export interface Milestone {
  id: string;
  goal_id: string;
  title: string;
  description: string;
  target_deadline?: string | null;
  completed_at?: string | null;
  position: number;
  created_at: string;
  updated_at: string;
}

/** Project linked to goal via projects.goal_id (not through milestone). */
export interface GoalProject {
  id: string;
  title: string;
  status: string;
}

export interface TaskProgress {
  total: number;
  done: number;
}

export interface ActivityItem {
  type: string;
  title: string;
  ref_id?: string;
  ref_slug?: string | null;
  timestamp: string;
}

// === Plan — Areas ===

/**
 * GET /api/admin/commitment/areas/{id} — a PARA area plus the goals and
 * projects filed under it. Mirrors `areaDetailResponse`
 * (internal/goal/handler.go): `goals` reuse the goal-list `GoalSummary` shape,
 * `projects` are minimal references. Both are always arrays (never null),
 * empty when the area has no children.
 */
export interface AreaDetail {
  area: AreaInfo;
  goals: GoalSummary[];
  projects: AreaProject[];
}

/** The area header on the area-detail response. */
export interface AreaInfo {
  id: string;
  slug: string;
  name: string;
  description: string;
  status: string;
  sort_order: number;
  created_at: string;
  updated_at: string;
}

/** A project filed under an area; links by id to the project detail. */
export interface AreaProject {
  id: string;
  title: string;
  status: string;
}

// === Plan — Projects ===

export interface ProjectSummary {
  id: string;
  title: string;
  slug: string;
  status: string;
  area: string;
  goal_breadcrumb: GoalBreadcrumb | null;
  task_progress: TaskProgress;
  staleness_days: number;
  last_activity_at: string | null;
}

export interface GoalBreadcrumb {
  goal_id: string;
  goal_title: string;
}

export interface ProjectDetail {
  id: string;
  title: string;
  slug: string;
  description: string;
  problem: string | null;
  solution: string | null;
  architecture: string | null;
  status: string;
  area: string;
  goal_breadcrumb: GoalBreadcrumb | null;
  // null when the project handler runs without a todo store wired (the Go
  // `todos_by_state` is an uninitialised `any` in that path); consumers guard.
  todos_by_state: TodosByState | null;
  recent_activity: ActivityItem[];
  related_content: ContentSummary[];
}

export interface TodosByState {
  in_progress: TaskSummary[];
  todo: TaskSummary[];
  done: TaskSummary[];
  someday: TaskSummary[];
}

export interface TaskSummary {
  id: string;
  title: string;
  priority: string;
  energy: string;
  due: string | null;
  is_in_today_plan: boolean;
}

export interface ContentSummary {
  id: string;
  title: string;
  type: ContentType;
  slug: string;
}

// === System health ===

/**
 * GET /api/admin/system/health envelope. Per-domain health is read off
 * the sub-shapes (feeds.failing > 0, pipelines.failed > 0); there is no
 * top-level state aggregate.
 */
export interface SystemHealth {
  feeds: FeedHealth;
  pipelines: PipelineHealth;
  database: DatabaseStats;
}

export interface FeedHealth {
  total: number;
  healthy: number;
  failing: number;
  failing_feeds: FailingFeed[];
}

export interface FailingFeed {
  name: string;
  error: string;
  /** Absent when the failure window start is unknown (backend omitempty). */
  since?: string;
}

export interface PipelineHealth {
  recent_runs: number;
  failed: number;
  last_run_at: string | null;
}

export interface DatabaseStats {
  contents_count: number;
  todos_count: number;
  notes_count: number;
}

// === System stats ===

/**
 * GET /api/admin/system/stats envelope (internal/stats/stats.go
 * Overview). Counts are point-in-time inventory aggregates; the
 * breakdown maps key on backend enum values (status, type, source).
 */
export interface StatsOverview {
  contents: StatsContents;
  collected: StatsCollected;
  feeds: StatsFeeds;
  process_runs: Record<string, StatsProcessRuns>;
  projects: StatsProjects;
  notes: StatsNotes;
  activity: StatsActivity;
}

export interface StatsContents {
  total: number;
  by_status: Record<string, number>;
  by_type: Record<string, number>;
  published: number;
}

export interface StatsCollected {
  total: number;
  by_status: Record<string, number>;
}

export interface StatsFeeds {
  total: number;
  enabled: number;
}

/** Per process-run kind (map key: crawl, agent_schedule, ...). */
export interface StatsProcessRuns {
  total: number;
  by_status: Record<string, number>;
}

export interface StatsProjects {
  total: number;
  by_status: Record<string, number>;
}

export interface StatsNotes {
  total: number;
  by_type: Record<string, number>;
}

export interface StatsActivity {
  total: number;
  last_24h: number;
  last_7d: number;
  by_source: Record<string, number>;
}

/** GET /api/admin/system/stats/drift — goal attention vs activity share. */
export interface DriftReport {
  period: string;
  areas: AreaDrift[];
}

export interface AreaDrift {
  area: string;
  active_goals: number;
  event_count: number;
  event_percent: number;
  goal_percent: number;
  drift_percent: number;
}

/** GET /api/admin/system/stats/learning — note growth + weekly cadence. */
export interface StatsLearning {
  notes: StatsNoteGrowth;
  activity: StatsWeeklyActivity;
}

export interface StatsNoteGrowth {
  total: number;
  last_week: number;
  last_month: number;
  by_type: Record<string, number>;
}

export interface StatsWeeklyActivity {
  this_week: number;
  last_week: number;
  trend: 'up' | 'down' | 'stable';
}

