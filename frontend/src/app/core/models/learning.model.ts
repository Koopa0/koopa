/**
 * Learning-domain wire types. Kept separate from workbench.model.ts
 * so learning surfaces can import without pulling the whole admin
 * workbench type graph.
 */

export type ConceptKind = 'pattern' | 'skill' | 'principle';
export type MasteryStage = 'struggling' | 'developing' | 'solid';
export type LearningDomain = string; // free-form per concept row
export type LearningSessionMode =
  | 'retrieval'
  | 'practice'
  | 'mixed'
  | 'review'
  | 'reading';

export type ObservationSignal = 'weakness' | 'improvement' | 'mastery';
export type ObservationConfidence = 'high' | 'low';

export interface MasteryCounts {
  weakness: number;
  improvement: number;
  mastery: number;
}

// === Dashboard ===

export interface DashboardConceptRow {
  slug: string;
  kind: ConceptKind;
  domain: LearningDomain;
  obs_count: number;
  mastery_value: number;
  mastery_stage: MasteryStage;
}

export interface DashboardObservation {
  id: string;
  signal: ObservationSignal;
  category: string;
  body: string;
  domain: LearningDomain;
  concept_slug: string;
  confidence: ObservationConfidence;
  created_at: string;
}

export interface DashboardOverview {
  streak_days: number;
  concepts: {
    count_total: number;
    counts_by_domain: Record<string, number>;
    rows: DashboardConceptRow[];
  };
  recent_observations: DashboardObservation[];
}

// === Concepts ===

export interface ConceptRow {
  slug: string;
  kind: ConceptKind;
  domain: LearningDomain;
  mastery_stage: MasteryStage;
  mastery_counts: MasteryCounts;
  obs_count: number;
  parent_slug: string | null;
}

export interface ConceptRelation {
  type: string;
  concept: { slug: string; name: string };
}

export interface ConceptLinkedNote {
  id: string;
  title: string;
  kind: string;
  maturity: string;
}

export interface ConceptLinkedContent {
  id: string;
  title: string;
  type: string;
}

export interface ConceptRecentAttempt {
  id: string;
  target_title: string;
  outcome: string;
  created_at: string;
}

/**
 * Concept detail wire shape returned by GET /concepts/:slug?domain=...
 * Intentionally NOT extending ConceptRow: the detail endpoint omits
 * obs_count / parent_slug (those are list-only concerns)
 * and adds name / description / low_confidence_counts plus the structural
 * sub-objects below.
 */
export interface ConceptProfile {
  slug: string;
  kind: ConceptKind;
  domain: LearningDomain;
  name: string;
  description: string;
  mastery_stage: MasteryStage;
  mastery_counts: MasteryCounts;
  low_confidence_counts: MasteryCounts;
  parent: { slug: string; name: string } | null;
  children: { slug: string; name: string }[];
  relations: ConceptRelation[];
  linked_notes: ConceptLinkedNote[];
  linked_contents: ConceptLinkedContent[];
  recent_attempts: ConceptRecentAttempt[];
  recent_observations: DashboardObservation[];
}

// === Sessions ===

export interface LearningSessionRow {
  id: string;
  domain: LearningDomain;
  mode: LearningSessionMode;
  started_at: string;
  ended_at: string | null;
  attempt_count: number;
  solved_independent_count: number;
  observation_count: number;
  reflection_note_id?: string | null;
}

export interface SessionAttemptObservation {
  id: string;
  signal: ObservationSignal;
  category: string;
  body: string;
  concept_slug: string;
  severity?: 'critical' | 'moderate' | 'minor' | null;
  confidence: ObservationConfidence;
}

export interface SessionAttempt {
  id: string;
  target: { id: string; title: string };
  paradigm: string;
  outcome: string;
  duration_minutes: number | null;
  stuck_at: string | null;
  approach: string | null;
  created_at: string;
  observations: SessionAttemptObservation[];
}

export interface SessionReflectionNote {
  id: string;
  kind: 'reflection';
  body_md: string;
  actor: string;
  created_at: string;
}

export interface SessionSummary {
  attempts: number;
  solved_independent: number;
  solved_with_hint: number;
  observations: number;
}

export interface SessionDetail {
  id: string;
  domain: LearningDomain;
  mode: LearningSessionMode;
  started_at: string;
  ended_at: string | null;
  summary: SessionSummary;
  attempts: SessionAttempt[];
  reflection_note: SessionReflectionNote | null;
}

// === Plans ===

/**
 * Plan entry lifecycle (learning_plan_entries.status):
 * planned → completed | skipped | substituted.
 */
export type PlanEntryStatus =
  | 'planned'
  | 'completed'
  | 'skipped'
  | 'substituted';

export type PlanStatus =
  | 'draft'
  | 'active'
  | 'paused'
  | 'completed'
  | 'abandoned';

/**
 * A learning plan row (internal/learning/plan Plan). Both the list endpoint
 * (`GET /plans` — draft + active only) and the `plan` key of the detail
 * envelope use this shape. The list endpoint carries NO progress data;
 * progress lives only on the detail envelope.
 */
export interface Plan {
  id: string;
  title: string;
  description: string;
  domain: string;
  goal_id?: string | null;
  status: PlanStatus;
  target_count?: number | null;
  plan_config?: unknown;
  created_by: string;
  created_at: string;
  updated_at: string;
}

/**
 * Plan entry projection from the detail envelope (EntryDetail in Go).
 * `plan_entry_id` is the identifier passed back to the update / remove /
 * reorder endpoints; `substituted_by` references another plan entry.
 * `phase` is a free-form kebab-case label (e.g. "foundation", "1-arrays").
 */
export interface PlanEntryDetail {
  plan_entry_id: string;
  plan_id: string;
  learning_target_id: string;
  position: number;
  status: PlanEntryStatus;
  phase?: string | null;
  substituted_by?: string | null;
  completed_by_attempt_id?: string | null;
  reason?: string | null;
  added_at: string;
  completed_at?: string | null;
  target_title: string;
  target_domain: string;
  target_difficulty?: string | null;
  target_external_id?: string | null;
}

/** Five-field completion summary from the detail envelope. */
export interface PlanProgress {
  total: number;
  completed: number;
  skipped: number;
  substituted: number;
  remaining: number;
}

/** `GET /plans/{id}` (and the reorder response) — de-embedded envelope. */
export interface PlanDetail {
  plan: Plan;
  entries: PlanEntryDetail[];
  progress: PlanProgress;
}
