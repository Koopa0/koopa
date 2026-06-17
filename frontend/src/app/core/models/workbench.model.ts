/**
 * Admin Workbench models — aligned with backend Go structs.
 *
 * Source of truth:
 *   Content    → internal/content/content.go
 *   Hypothesis → internal/hypothesis/hypothesis.go
 *   Agent      → internal/agent/agent.go + registry.go
 *   Goal       → internal/goal/goal.go
 *   Todo       → internal/todo/todo.go
 *   Daily      → internal/daily/daily.go
 *
 * Vocabulary discipline:
 *   hypothesis ≠ insight — schema is `hypotheses`, never `insights`
 *   agent ≠ participant — schema is `agents`
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
// Agent (matches internal/agent/handler.go::agentResponse +
// internal/agent/registry.go::BuiltinAgents)
//
// The agents table is a read-only identity projection. The HTTP shape is
// exactly six fields — there is no capability, task, or activity concept
// (the MCP-v3 contraction retired the A2A coordination surface).
// ============================================================

/**
 * Platform an agent runs on. Matches the `platform` literals in
 * registry.go::BuiltinAgents — `system` is the DB-level fallback identity.
 */
export type AgentPlatform =
  | 'claude-cowork'
  | 'claude-code'
  | 'claude-web'
  | 'codex'
  | 'human'
  | 'system';

export type AgentStatus = 'active' | 'retired';

/**
 * Agent — the full read-only registry projection. Mirrors
 * `agentResponse` in internal/agent/handler.go: six fields, `schedule`
 * present only for agents that carry one (e.g. planner's morning briefing).
 */
export interface Agent {
  name: string;
  display_name: string;
  platform: AgentPlatform;
  description: string;
  schedule?: AgentSchedule;
  status: AgentStatus;
}

/**
 * Schedule attached to an agent. Mirrors `scheduleResponse` in
 * internal/agent/handler.go — definitions live in the Go registry, not
 * the DB.
 */
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
// Cell state — envelope carried by any summary cell.
// ============================================================

export type CellStateLevel = 'ok' | 'warn' | 'error';

export interface CellState {
  state: CellStateLevel;
  reason?: string;
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
  domains: DomainMastery[];
}

// ============================================================
// Agents (read-only registry projection)
//
// GET /api/admin/system/agents returns a bare []Agent; the single-agent
// route returns one Agent. Both rows and detail carry the same six
// fields — list and detail are identical shapes.
// ============================================================

/** Row shape for the agents roster — the full registry projection. */
export type AgentSummary = Agent;

/** Single-agent detail — same six-field projection as the roster row. */
export type AgentDetail = Agent;

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
  | 'agent';

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
    bgClass: 'bg-brand/30',
    textClass: 'text-brand',
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
    bgClass: 'bg-overlay',
    textClass: 'text-fg-muted',
    label: 'Project',
  },
  todo: {
    abbrev: 'TD',
    bgClass: 'bg-overlay',
    textClass: 'text-fg-muted',
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
};
