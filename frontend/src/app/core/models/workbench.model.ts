/**
 * Admin Workbench models — aligned with backend Go structs.
 *
 * Source of truth:
 *   Content    → internal/content/content.go
 *   Hypothesis → internal/hypothesis/hypothesis.go
 *   Task       → internal/agent/task/task.go
 *   Artifact   → internal/agent/artifact/artifact.go
 *   Agent      → internal/agent/agent.go + registry.go
 *   Goal       → internal/goal/goal.go
 *   Todo       → internal/todo/todo.go
 *   Daily      → internal/daily/daily.go
 *
 * Vocabulary discipline:
 *   task ≠ todo    — task is A2A coordination, todo is personal GTD
 *   hypothesis ≠ insight — schema is `hypotheses`, never `insights`
 *   agent ≠ participant — schema is `agents`
 *   agent_note ≠ journal — schema is `agent_notes`
 */

import type { ContentStatus, ContentType, GoalStatus } from './api.model';

// ============================================================
// Content (matches internal/content/content.go::Content)
// ============================================================

export interface WorkbenchContent {
  id: string;
  slug: string;
  title: string;
  body: string;
  excerpt: string;
  type: ContentType;
  status: ContentStatus;
  tags: string[];
  topics: TopicRef[];
  origin_ref?: string;
  origin_system?: OriginSystem;
  is_public: boolean;
  project_id?: string;
  ai_metadata?: ContentAiMetadata;
  reading_time_min: number;
  cover_image?: string;
  published_at?: string;
  created_at: string;
  updated_at: string;
}

export type OriginSystem = 'ai-generated' | 'manual';

export interface TopicRef {
  id: string;
  slug: string;
  name: string;
}

export interface ContentAiMetadata {
  summary?: string;
  keywords?: string[];
  quality_score?: number;
  review_notes?: string;
  review_rejected_at?: string;
  [key: string]: unknown;
}

// ============================================================
// Hypothesis (matches internal/hypothesis/hypothesis.go::Record)
// ============================================================

export type HypothesisState =
  | 'unverified'
  | 'verified'
  | 'invalidated'
  | 'archived';

export interface Hypothesis {
  id: string;
  created_by: string;
  content: string;
  state: HypothesisState;
  claim: string;
  invalidation_condition: string;
  metadata?: HypothesisMetadata;
  observed_date: string;
  created_at: string;
}

export interface HypothesisMetadata {
  supporting_evidence?: unknown[];
  counter_evidence?: unknown[];
  conclusion?: string;
  category?: string;
  project?: string;
  tags?: string[];
  [key: string]: unknown;
}

// ============================================================
// Task — A2A coordination (matches internal/agent/task/task.go)
// ============================================================

export type TaskState =
  | 'submitted'
  | 'working'
  | 'completed'
  | 'canceled'
  | 'revision_requested';

export type MessageRole = 'request' | 'response';

export interface CoordinationTask {
  id: string;
  source: string;
  target: string;
  title: string;
  state: TaskState;
  submitted_at: string;
  accepted_at?: string;
  completed_at?: string;
  canceled_at?: string;
  revision_requested_at?: string;
  metadata?: Record<string, unknown>;
}

export interface TaskMessage {
  id: string;
  task_id: string;
  role: MessageRole;
  position: number;
  parts: A2aPart[];
  created_at: string;
}

/**
 * a2a-go Part — matches a2a-go's flattened JSON format.
 *
 * Wire format (from a2a-go MarshalJSON):
 *   Text part: {"text": "hello"}
 *   Data part: {"data": {"mimeType": "image/png", "data": "base64..."}}
 *
 * Discriminated by which field is present, NOT by a `kind` field.
 */
export interface A2aTextPart {
  text: string;
  data?: never;
}

export interface A2aDataPart {
  text?: never;
  data: {
    mimeType: string;
    data: string;
  };
}

export type A2aPart = A2aTextPart | A2aDataPart;

/** Type guard for text parts. */
export function isTextPart(part: A2aPart): part is A2aTextPart {
  return 'text' in part && typeof part.text === 'string';
}

// ============================================================
// Artifact (matches internal/agent/artifact/artifact.go)
// ============================================================

export interface Artifact {
  id: string;
  task_id: string;
  name: string;
  description?: string;
  parts: A2aPart[];
  created_at: string;
}

// ============================================================
// Agent (matches internal/agent/agent.go)
// ============================================================

export type AgentPlatform =
  | 'claude-cowork'
  | 'claude-code'
  | 'claude-web'
  | 'human';

export type AgentStatus = 'active' | 'retired';

export interface Agent {
  name: string;
  display_name: string;
  platform: AgentPlatform;
  description: string;
  capability: AgentCapability;
  schedule?: AgentSchedule;
  status: AgentStatus;
}

export interface AgentCapability {
  submit_tasks: boolean;
  receive_tasks: boolean;
  publish_artifacts: boolean;
}

export interface AgentSchedule {
  name: string;
  trigger: 'cron' | 'manual' | '';
  expr: string;
  backend: string;
  purpose: string;
}

// ============================================================
// Goal detail (matches internal/goal/store.go::GoalProgress)
// ============================================================

export interface WorkbenchGoalDetail {
  id: string;
  title: string;
  description: string;
  status: GoalStatus;
  area_id?: string;
  area_name?: string;
  deadline?: string;
  quarter: string;
  milestones: GoalMilestone[];
  projects: GoalLinkedProject[];
  recent_activity: GoalActivityItem[];
  created_at: string;
}

export interface GoalMilestone {
  id: string;
  title: string;
  completed: boolean;
  completed_at?: string;
  position: number;
}

export interface GoalLinkedProject {
  id: string;
  title: string;
  status: string;
}

export interface GoalActivityItem {
  type: string;
  title: string;
  timestamp: string;
}

// ============================================================
// Goal summary (for overview grid)
// ============================================================

export interface GoalSummary {
  id: string;
  title: string;
  status: GoalStatus;
  deadline?: string;
  milestones_total: number;
  milestones_done: number;
  area_name: string;
}

// ============================================================
// Cell state — envelope carried by any summary cell.
// ============================================================

export type CellStateLevel = 'ok' | 'warn' | 'error';

export interface CellState {
  state: CellStateLevel;
  reason?: string;
}

// ============================================================
// Daily Plan (matches internal/daily/daily.go::Item)
// ============================================================

export type DailyPlanStatus = 'planned' | 'done' | 'deferred' | 'dropped';

export interface DailyPlanItem {
  id: string;
  todo_id: string;
  todo_title: string;
  todo_state: string;
  todo_assignee: string;
  todo_due?: string;
  todo_energy?: string | null;
  todo_priority?: string | null;
  status: DailyPlanStatus;
  position: number;
  reason?: string;
  selected_by: string;
  project_title?: string;
  project_slug?: string;
}

export interface DailyPlanResponse extends CellState {
  date: string;
  items: DailyPlanItem[];
  total: number;
  done: number;
  overdue_count: number;
}

// ============================================================
// Learning Summary (matches internal/learning/handler.go response)
// ============================================================

export interface DomainMastery {
  domain: string;
  concepts_total: number;
  concepts_mastered: number;
  concepts_weak: number;
  concepts_developing: number;
}

export interface LearningSummary extends CellState {
  streak_days: number;
  due_reviews: number;
  domains: DomainMastery[];
}

// ============================================================
// Agents (cell-state aware list)
// ============================================================

export type AgentActivityState = 'active' | 'idle' | 'blocked';

export interface AgentSummary extends Agent {
  open_task_count: number;
  blocked_count: number;
  activity_state: AgentActivityState;
  /** Optional: enables AGENTS cell ⚠ badge → direct open of blocking Task Inspector. */
  first_blocked_task_id?: string | null;
}

/**
 * Agent Inspector detail — v1 brief shape.
 * See: frontend/docs/inspector-design/agent-inspector.md
 *
 * v1 deltas vs AgentSummary:
 * - +retired_at — present when status='retired' (DB chk_agent_status_retired)
 * - +schedule_human_readable — server-derived "Daily 8 AM briefing" from cron + purpose
 * - +last_task_accepted_at — optional MAX(tasks.accepted_at WHERE assignee=$1) for footer hint
 */
export interface AgentDetail extends AgentSummary {
  retired_at?: string | null;
  schedule_human_readable?: string | null;
  last_task_accepted_at?: string | null;
}

export interface AgentsResponse extends CellState {
  agents: AgentSummary[];
}

// ============================================================
// Judgment Queue (frontend-composed from 3 sources)
// ============================================================

export type JudgmentItemType = 'content' | 'task' | 'hypothesis';

export interface JudgmentQueueItem {
  type: JudgmentItemType;
  id: string;
  title: string;
  subtitle: string;
  submitted_at: string;
  age_days: number;
}

// ============================================================
// Todo Inspector — matches GET /api/admin/commitment/todos/{id} response.
// ============================================================

export type TodoState = 'inbox' | 'todo' | 'in_progress' | 'done' | 'someday';

export type EnergyLevel = 'low' | 'medium' | 'high';
export type PriorityLevel = 'low' | 'medium' | 'high';

/**
 * Todo Inspector detail — v1 brief shape.
 * See: frontend/docs/inspector-design/todo-inspector.md
 *
 * v1 vs v0 (template-copy era) deltas:
 * - +created_by — surface who put this in inbox (≠ assignee = delegation signal)
 * - +recent_skip_count_30d — health signal for recurring todos (todo_skips table)
 */
export interface TodoDetail {
  id: string;
  title: string;
  state: TodoState;
  description: string;
  due?: string | null;
  energy?: EnergyLevel | null;
  priority?: PriorityLevel | null;
  recur_interval?: number | null;
  recur_unit?: string | null;
  completed_at?: string | null;
  project_id?: string | null;
  project_title: string;
  project_slug: string;
  assignee: string;
  /** Who put this todo into the system. ≠ assignee signals delegation. */
  created_by: string;
  /** Count of todo_skips rows in last 30 days. Only set when recur_interval IS NOT NULL. */
  recent_skip_count_30d?: number | null;
  created_at: string;
  updated_at: string;
}

// ============================================================
// Agent Inspector — uses AgentSummary (above) + AgentTasksResponse.
// ============================================================

export interface TaskBrief {
  id: string;
  title: string;
  state: TaskState;
  source: string;
  target: string;
  submitted_at: string;
  completed_at?: string | null;
}

export interface ArtifactBrief {
  id: string;
  task_id: string;
  task_title: string;
  name: string;
  description?: string | null;
  created_at: string;
}

export interface AgentTasksResponse {
  as_assignee: TaskBrief[];
  as_creator: TaskBrief[];
  recent_artifacts: ArtifactBrief[];
}

// ============================================================
// Concept Inspector — matches GET /api/admin/learning/concepts/{id} response.
// ============================================================

export type MasteryStage = 'developing' | 'struggling' | 'solid';
export type ObservationSignal = 'weakness' | 'improvement' | 'mastery';
export type ObservationSeverity = 'critical' | 'moderate' | 'minor';

/**
 * Concept Inspector detail. `low_confidence_observations` stays in a
 * `<details>` progressive disclosure — confidence is a read-time
 * label, never a write-time gate. `recent_attempts` caps at 5.
 */
export interface ConceptDetail {
  id: string;
  slug: string;
  name: string;
  domain: string;
  kind: string;
  description: string;
  created_at: string;
  mastery_stage: MasteryStage;
  mastery_counts: {
    weakness: number;
    improvement: number;
    mastery: number;
    total: number;
  };
  recent_attempts: ConceptAttempt[]; // top 5
  recent_observations: ConceptObservation[]; // high-confidence only

  // NEW v1
  parent_concept?: { id: string; slug: string; name: string } | null;
  low_confidence_count: number;
  low_confidence_observations: ConceptObservation[];
  targets_exercising_count: number;
}

export interface ConceptAttempt {
  id: string;
  outcome: string;
  duration_minutes?: number | null;
  attempted_at: string;
  target_title: string;
}

export interface ConceptObservation {
  id: string;
  signal_type: ObservationSignal;
  category: string;
  severity?: ObservationSeverity | null;
  detail: string;
  created_at: string;
  attempted_at?: string | null;
  target_title: string;
}

// ============================================================
// ============================================================
// Bookmark Inspector — matches GET /api/admin/knowledge/bookmarks/{id} response.
// ============================================================

/**
 * Bookmark Inspector detail. The backend extracts `host` from the URL
 * and joins `source_feed_name` via `feed_entries` when the bookmark
 * came from an RSS source.
 */
export interface BookmarkDetail {
  id: string;
  url: string;
  url_hash: string;
  slug: string;
  title: string;
  excerpt: string;
  note: string;
  capture_channel: 'rss' | 'manual' | 'shared' | string;
  source_feed_entry_id?: string | null;
  curated_by: string;
  curated_at: string;
  is_public: boolean;
  published_at?: string | null;
  topics: TopicRef[];
  tags: string[];
  created_at: string;
  updated_at: string;

  // NEW v1
  host?: string | null;
  source_feed_name?: string | null;
}

// ============================================================
// Inspector target types
// ============================================================

/**
 * @deprecated The inspector-based routing model is being phased out in favor
 * of route-based navigation. New code MUST route directly to a domain page
 * (e.g. `/admin/knowledge/content/:id`) instead of opening an inspector
 * panel keyed by InspectorTargetType. Kept for existing legacy callers
 * until the migration completes.
 */
export type InspectorTargetType =
  | 'content'
  | 'hypothesis'
  | 'task'
  | 'goal'
  | 'project'
  | 'todo'
  | 'concept'
  | 'agent'
  | 'bookmark';

/** @deprecated See InspectorTargetType. */
export interface InspectorTarget {
  type: InspectorTargetType;
  id: string;
}

// ============================================================
// Entity type metadata (for badges, icons, colors)
// ============================================================

export interface EntityTypeMeta {
  abbrev: string;
  bgClass: string;
  textClass: string;
  label: string;
}

export const ENTITY_TYPE_META: Record<InspectorTargetType, EntityTypeMeta> = {
  content: {
    abbrev: 'ART',
    bgClass: 'bg-sky-900/30',
    textClass: 'text-sky-400',
    label: 'Content',
  },
  task: {
    abbrev: 'TSK',
    bgClass: 'bg-amber-900/30',
    textClass: 'text-amber-400',
    label: 'Task',
  },
  hypothesis: {
    abbrev: 'HYP',
    bgClass: 'bg-purple-900/30',
    textClass: 'text-purple-400',
    label: 'Hypothesis',
  },
  goal: {
    abbrev: 'GL',
    bgClass: 'bg-emerald-900/30',
    textClass: 'text-emerald-400',
    label: 'Goal',
  },
  project: {
    abbrev: 'PRJ',
    bgClass: 'bg-zinc-700',
    textClass: 'text-zinc-300',
    label: 'Project',
  },
  todo: {
    abbrev: 'TD',
    bgClass: 'bg-zinc-700',
    textClass: 'text-zinc-400',
    label: 'Todo',
  },
  concept: {
    abbrev: 'CPT',
    bgClass: 'bg-indigo-900/30',
    textClass: 'text-indigo-400',
    label: 'Concept',
  },
  agent: {
    abbrev: 'AGT',
    bgClass: 'bg-orange-900/30',
    textClass: 'text-orange-400',
    label: 'Agent',
  },
  bookmark: {
    abbrev: 'BK',
    bgClass: 'bg-pink-900/30',
    textClass: 'text-pink-400',
    label: 'Bookmark',
  },
};
