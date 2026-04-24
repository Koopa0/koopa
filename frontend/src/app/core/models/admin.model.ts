/** Admin workbench models. */

import type { ContentType, GoalStatus } from './api.model';
import type { CellState } from './workbench.model';

// === Plan — Goals ===

/**
 * GET /api/admin/commitment/goals response — flat `goals` array with `area_name` per goal
 * and cell-state envelope.
 */
export interface GoalsOverview extends CellState {
  goals: ActiveGoalSummary[];
}

/**
 * Per-goal summary for overview grid. `area_name` is flat (not grouped).
 * `last_progress_at` + `stalled_days` drive GOALS cell warn state.
 */
export interface ActiveGoalSummary {
  id: string;
  title: string;
  area_name: string;
  status: GoalStatus;
  milestones_total: number;
  milestones_done: number;
  /** ISO datetime — most recent milestone completion (or goal creation). */
  last_progress_at?: string;
  /** null when not stalled; >=14d triggers cell warn. */
  stalled_days?: number | null;
  deadline?: string | null;
  quarter?: string;
}

/** Goal detail — milestones and projects are siblings, not parent-child */
export interface GoalDetail {
  id: string;
  title: string;
  description: string;
  status: GoalStatus;
  area_id: string;
  area_name: string;
  deadline: string | null;
  quarter: string;
  created_at: string;
  health: GoalHealth;
  milestones: Milestone[];
  projects: GoalProject[];
  recent_activity: ActivityItem[];
}

export type GoalHealth = 'on-track' | 'at-risk' | 'stalled';

/** Milestone — binary completion (completed_at null = not completed) */
export interface Milestone {
  id: string;
  title: string;
  completed: boolean;
  completed_at: string | null;
  position: number;
}

/** Project linked to goal via projects.goal_id (not through milestone) */
export interface GoalProject {
  id: string;
  title: string;
  status: string;
  task_progress: TaskProgress;
}

export interface TaskProgress {
  total: number;
  done: number;
}

export interface ActivityItem {
  type: string;
  title: string;
  timestamp: string;
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
  todos_by_state: TodosByState;
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

// === Learn ===

export interface LearningDashboard {
  due_reviews_count: number;
  due_reviews_today: number;
  recent_sessions: SessionSummary[];
  weakness_spotlight: ConceptWeakness[];
  mastery_by_domain: DomainMastery[];
  streak: LearningStreak;
}

export interface SessionSummary {
  id: string;
  domain: string;
  mode: string;
  started_at: string;
  ended_at: string | null;
  duration_minutes: number;
  attempts_count: number;
  solved_count: number;
}

export interface DomainMastery {
  domain: string;
  concepts_total: number;
  concepts_mastered: number;
  concepts_weak: number;
  concepts_developing: number;
}

export interface SeveritySummary {
  critical: number;
  moderate: number;
  minor: number;
}

export interface ConceptWeakness {
  concept_slug: string;
  concept_name: string;
  domain: string;
  category: string;
  fail_count_30d: number;
  severity_summary: SeveritySummary;
  severity_score: number;
  last_practiced: string | null;
  days_since_practice: number | null;
}

export interface LearningStreak {
  current_days: number;
}

// === Learning Plans ===

export type PlanStatus =
  | 'draft'
  | 'active'
  | 'paused'
  | 'completed'
  | 'abandoned';
export type PlanItemStatus =
  | 'planned'
  | 'completed'
  | 'skipped'
  | 'substituted';

export interface LearningPlanSummary {
  id: string;
  title: string;
  domain: string;
  status: PlanStatus;
  items_total: number;
  items_completed: number;
  items_skipped: number;
  created_at: string;
  updated_at: string;
}

export interface LearningPlanDetail {
  id: string;
  title: string;
  domain: string;
  status: PlanStatus;
  description: string;
  items: PlanItemDetail[];
  progress: PlanProgress;
}

export interface PlanItemDetail {
  id: string;
  learning_item_id: string;
  title: string;
  difficulty: ItemDifficulty | null;
  position: number;
  status: PlanItemStatus;
  completed_at: string | null;
  reason: string | null;
}

export interface PlanProgress {
  total: number;
  completed: number;
  skipped: number;
  substituted: number;
  planned: number;
}

// === Schema-aligned enums (from migrations/001_initial.up.sql) ===

/** attempt.outcome — 7 values, covering both problem-solving and immersive paradigms */
export type AttemptOutcome =
  | 'solved_independent'
  | 'solved_with_hint'
  | 'solved_after_solution'
  | 'completed'
  | 'completed_with_support'
  | 'incomplete'
  | 'gave_up';

/** sessions.session_mode */
export type SessionMode =
  | 'retrieval'
  | 'practice'
  | 'mixed'
  | 'review'
  | 'reading';

/** attempt_observations.signal_type */
export type ObservationSignal = 'weakness' | 'improvement' | 'mastery';

/** attempt_observations.severity — only has a value for weakness */
export type ObservationSeverity = 'minor' | 'moderate' | 'critical';

/** concepts.kind */
export type ConceptKind = 'pattern' | 'skill' | 'principle';

/** items.difficulty */
export type ItemDifficulty = 'easy' | 'medium' | 'hard';

// === System health ===

/**
 * GET /api/admin/system/health envelope. `state` warns when any feed
 * is failing or when 24h pipeline_runs.failed > 0.
 */
export interface SystemHealth extends CellState {
  feeds: FeedHealth;
  pipelines: PipelineHealth;
  ai_budget: AiBudget;
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
  since: string;
}

export interface PipelineHealth {
  recent_runs: number;
  failed: number;
  last_run_at: string | null;
}

export interface AiBudget {
  today_tokens: number;
  daily_limit: number;
}

export interface DatabaseStats {
  contents_count: number;
  tasks_count: number;
  notes_count: number;
}
