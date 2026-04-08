/** Admin redesign models — matches API spec in docs/ADMIN-API-REQUIREMENTS.md */

import type {
  ContentType,
  ContentStatus,
  GoalStatus,
  InsightStatus,
  ReviewLevel,
  TaskStatus,
} from './api.model';

// === Today ===

export interface MyDayContext {
  date: string;
  context_line: string;
  yesterday_unfinished: DailyPlanItem[];
  today_plan: DailyPlanItem[];
  overdue_tasks: OverdueTask[];
  needs_attention: NeedsAttention;
  goal_pulse: GoalPulse[];
}

export interface DailyPlanItem {
  id: string;
  task_id: string;
  title: string;
  area: string;
  energy: string;
  estimated_minutes: number | null;
  position: number;
  status: DailyPlanItemStatus;
  planned_date: string;
}

export type DailyPlanItemStatus = 'planned' | 'done' | 'deferred' | 'dropped';
export type DailyItemAction = 'complete' | 'defer' | 'drop';

export interface OverdueTask {
  id: string;
  title: string;
  due: string;
  area: string;
  priority: string;
}

export interface NeedsAttention {
  inbox_count: number;
  pending_directives: number;
  unread_reports: number;
  due_reviews: number;
  overdue_tasks: number;
}

export interface GoalPulse {
  id: string;
  title: string;
  area: string;
  deadline: string | null;
  days_remaining: number | null;
  milestones_total: number;
  milestones_done: number;
  next_milestone: string | null;
  status: GoalStatus;
}

// === Inbox ===

export interface InboxItem {
  id: string;
  text: string;
  source: InboxSource;
  captured_at: string;
  age_hours: number;
}

export type InboxSource = 'manual' | 'mcp' | 'rss';

export interface InboxStats {
  total: number;
  oldest_age_days: number;
  by_source: Record<string, number>;
}

export interface InboxResponse {
  items: InboxItem[];
  stats: InboxStats;
}

export type ClarifyType = 'task' | 'journal' | 'insight' | 'discard';

export interface ClarifyAsTask {
  type: 'task';
  area_id?: string;
  priority?: string;
  energy?: string;
  due?: string;
}

export interface ClarifyAsJournal {
  type: 'journal';
  kind: JournalKind;
  body: string;
}

export interface ClarifyAsInsight {
  type: 'insight';
  hypothesis: string;
  initial_evidence?: string;
}

export interface ClarifyAsDiscard {
  type: 'discard';
}

export type ClarifyDecision =
  | ClarifyAsTask
  | ClarifyAsJournal
  | ClarifyAsInsight
  | ClarifyAsDiscard;

export interface ClarifyResult {
  result: 'clarified';
  entity_type: string;
  entity_id: string;
}

// === Plan — Goals ===

export interface GoalsOverview {
  by_area: AreaGoals[];
}

export interface AreaGoals {
  area_id: string;
  area_name: string;
  area_slug: string;
  goals: GoalSummary[];
}

export interface GoalSummary {
  id: string;
  title: string;
  status: GoalStatus;
  deadline: string | null;
  days_remaining: number | null;
  milestones_total: number;
  milestones_done: number;
  next_milestone_title: string | null;
  projects_count: number;
  quarter: string;
}

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
  milestones: MilestoneWithProjects[];
  recent_activity: ActivityItem[];
}

export type GoalHealth = 'on-track' | 'at-risk' | 'stalled';

export interface MilestoneWithProjects {
  id: string;
  title: string;
  completed: boolean;
  completed_at: string | null;
  position: number;
  projects: ProjectInMilestone[];
}

export interface ProjectInMilestone {
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

export interface GoalProposal {
  title: string;
  description: string;
  area_id: string;
  deadline?: string;
  quarter?: string;
}

export interface GoalProposalResult {
  proposal_id: string;
  preview: GoalProposalPreview;
}

export interface GoalProposalPreview {
  title: string;
  area_name: string;
  deadline: string | null;
  existing_goals_in_area: number;
  quarter: string;
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
  milestone_id: string | null;
  milestone_title: string | null;
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
  tasks_by_status: TasksByStatus;
  recent_activity: ActivityItem[];
  related_content: ContentSummary[];
}

export interface TasksByStatus {
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

// === Plan — Tasks ===

export interface TaskBacklogItem {
  id: string;
  title: string;
  status: string;
  area: string;
  priority: string;
  energy: string;
  due: string | null;
  project_title: string | null;
  is_in_today_plan: boolean;
}

export type TaskAdvanceAction = 'start' | 'complete' | 'defer' | 'drop';

export interface TaskFilters {
  status: string | null;
  area_id: string | null;
  energy: string | null;
  priority: string | null;
  search: string;
}

// === Library ===

export interface ContentPipeline {
  drafts_needing_work: ContentPipelineItem[];
  in_review: ContentPipelineItem[];
  ready_to_publish: ContentPipelineItem[];
  recently_published: ContentPipelineItem[];
}

export interface ContentPipelineItem {
  id: string;
  title: string;
  type: ContentType;
  slug: string;
  updated_at: string;
  word_count: number | null;
  review_level: ReviewLevel | null;
  submitted_at: string | null;
  reviewed_at: string | null;
  published_at: string | null;
}

// === Learn (Phase 2) ===

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
  started_at: string;
  duration_minutes: number;
  attempts_count: number;
  solved_count: number;
}

export interface ConceptWeakness {
  concept_slug: string;
  concept_name: string;
  domain: string;
  fail_count_30d: number;
  last_practiced: string | null;
  days_since_practice: number | null;
}

export interface DomainMastery {
  domain: string;
  concepts_total: number;
  concepts_mastered: number;
  concepts_weak: number;
  concepts_untested: number;
}

export interface LearningStreak {
  current_days: number;
  longest: number;
}

// === Reflect (Phase 2) ===

export interface DailyReflectionContext {
  date: string;
  plan_vs_actual: PlanVsActual;
  completed_tasks: CompletedTask[];
  learning_sessions: SessionSummary[];
  content_changes: ContentChange[];
  commits_count: number;
  inbox_delta: InboxDelta;
}

export interface PlanVsActual {
  planned: number;
  completed: number;
  deferred: number;
  dropped: number;
}

export interface CompletedTask {
  id: string;
  title: string;
  area: string;
}

export interface ContentChange {
  title: string;
  type: ContentType;
  action: string;
}

export interface InboxDelta {
  captured: number;
  clarified: number;
  net: number;
}

export interface WeeklyReviewContext {
  week_start: string;
  week_end: string;
  goal_progress: GoalWeeklyDelta[];
  project_health: ProjectHealthItem[];
  learning_summary: WeeklyLearningSummary;
  content_output: WeeklyContentOutput;
  inbox_health: WeeklyInboxHealth;
  insights_needing_check: InsightCheck[];
  metrics: WeeklyMetrics;
}

export interface GoalWeeklyDelta {
  goal_title: string;
  milestones_completed_this_week: number;
  total_done: number;
  total: number;
}

export interface ProjectHealthItem {
  title: string;
  status: string;
  tasks_completed: number;
  stalled: boolean;
}

export interface WeeklyLearningSummary {
  sessions_count: number;
  total_minutes: number;
  concepts_improved: string[];
  concepts_declined: string[];
}

export interface WeeklyContentOutput {
  published: number;
  drafted: number;
}

export interface WeeklyInboxHealth {
  start_count: number;
  end_count: number;
  clarified: number;
  captured: number;
}

export interface InsightCheck {
  id: string;
  hypothesis: string;
  status: InsightStatus;
  age_days: number;
}

export interface WeeklyMetrics {
  tasks_completed: number;
  commits: number;
  build_logs: number;
}

export type JournalKind = 'plan' | 'reflection' | 'context' | 'metrics';

export interface JournalEntry {
  kind: JournalKind;
  body: string;
  date?: string;
}

// === Studio (Phase 3) ===

export interface StudioOverview {
  pending_directives: DirectiveSummary[];
  unread_reports: ReportSummary[];
  participants: ParticipantSummary[];
}

export interface DirectiveSummary {
  id: string;
  title: string;
  target: string;
  created_at: string;
  status: string;
}

export interface ReportSummary {
  id: string;
  title: string;
  source: string;
  directive_title: string | null;
  filed_at: string;
}

export interface ParticipantSummary {
  name: string;
  active_directives: number;
  recent_reports: number;
  capabilities: string[];
}

// === System (Phase 3) ===

export interface SystemHealth {
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
