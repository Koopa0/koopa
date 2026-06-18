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
  // Inert agent-drafted state (MCP v3.1): drafts surface only in the admin
  // hypotheses list, never in brief/Today/dashboards. The owner endorses
  // (draft → unverified) or deletes them; nothing else acts on a draft.
  | 'draft'
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
// Todo — shared enums (todo list / plan / detail views).
// ============================================================

export type TodoState = 'inbox' | 'todo' | 'in_progress' | 'done' | 'someday';

export type EnergyLevel = 'low' | 'medium' | 'high';
export type PriorityLevel = 'low' | 'medium' | 'high';

// ============================================================
// Concept — shared mastery / observation enums.
// ============================================================

export type MasteryStage = 'developing' | 'struggling' | 'solid';
export type ObservationSignal = 'weakness' | 'improvement' | 'mastery';
export type ObservationSeverity = 'critical' | 'moderate' | 'minor';
