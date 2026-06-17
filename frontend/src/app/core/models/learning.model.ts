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

/**
 * The single concept to practice next, for the dashboard Next-up card.
 * When `empty` is true the weakness signal is silent and only `reason`
 * carries a sentence; the concept fields are absent.
 */
export interface NextTarget {
  empty: boolean;
  reason: string;
  concept_slug?: string;
  concept_name?: string;
  domain?: string;
  mastery_stage?: MasteryStage;
  severity?: string;
  days_since_practice?: number;
}

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

/** One day of the dashboard week heatmap (7 days, zero-filled, today last). */
export interface WeekActivityDay {
  /** UTC day in YYYY-MM-DD form. */
  date: string;
  /** learning_attempts logged on that day. */
  attempts: number;
}

export interface DashboardOverview {
  streak_days: number;
  concepts: {
    count_total: number;
    counts_by_domain: Record<string, number>;
    rows: DashboardConceptRow[];
  };
  recent_observations: DashboardObservation[];
  week_activity: WeekActivityDay[];
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

/** One observation on an attempt (matches learning.Observation). */
export interface SessionAttemptObservation {
  id: string;
  attempt_id: string;
  concept_id: string;
  signal_type: ObservationSignal;
  category: string;
  severity?: 'critical' | 'moderate' | 'minor' | null;
  detail?: string | null;
  confidence: ObservationConfidence;
  position: number;
  concept_slug?: string;
  concept_name?: string;
}

/** One attempt in a session timeline (matches learning.Attempt). */
export interface SessionAttempt {
  id: string;
  learning_target_id: string;
  session_id: string;
  attempt_number: number;
  paradigm: string;
  outcome: string;
  duration_minutes?: number | null;
  stuck_at?: string | null;
  approach_used?: string | null;
  attempted_at: string;
  created_at?: string;
  target_title: string;
  target_external_id?: string | null;
  difficulty?: string | null;
  observations?: SessionAttemptObservation[];
  matched_observation_id?: string | null;
}

/** Session metadata block of the detail envelope (matches learning.Session). */
export interface SessionMeta {
  id: string;
  domain: LearningDomain;
  mode: LearningSessionMode;
  daily_plan_item_id?: string | null;
  started_at: string;
  ended_at?: string | null;
  created_at: string;
}

/**
 * GET /api/admin/learning/sessions/{id} wire: the lean session row plus its
 * attempts. Completion metrics (attempt counts, solved-independent rate) are
 * derived from `attempts` on the client; the endpoint carries no summary
 * block and no reflection note.
 */
export interface SessionDetail {
  session: SessionMeta;
  attempts: SessionAttempt[];
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
 * A learning plan row (internal/learning/plan Plan). This bare shape is the
 * `plan` key of the detail envelope. The list endpoint returns
 * {@link PlanSummary} (this plus per-plan entry counts).
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
 * A learning plan list row (internal/learning/plan Summary). Adds the
 * per-plan entry counts the admin list's Entries/Progress columns render.
 * `GET /plans` returns these; the detail envelope's `plan` key does not
 * carry the counts.
 */
export interface PlanSummary extends Plan {
  entry_total: number;
  entry_done: number;
}

/**
 * Lean plan-entry row returned by POST /plans/{id}/entries (Go `Entry`).
 * Distinct from PlanEntryDetail: it carries no target_* projection and its
 * id key is `id`. The add-entry caller reloads the detail and ignores this
 * body — it exists so the return type matches the actual wire.
 */
export interface PlanEntry {
  id: string;
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

/**
 * One attempt on a learning target, as returned newest-first by
 * GET /learning/targets/{id}/attempts. Backs the audit-gate modal's
 * attempt picker — the candidate `completed_by_attempt_id` values. Mirrors
 * the Go `learning.Attempt` wire shape; only the fields the picker reads
 * are typed (the wire carries more).
 */
export interface TargetAttempt {
  id: string;
  learning_target_id: string;
  session_id: string;
  attempt_number: number;
  paradigm: string;
  outcome: string;
  duration_minutes?: number;
  attempted_at: string;
  target_title: string;
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
  /** Linked goal's title for the meta strip; `""` when the plan has no goal. */
  goal_name: string;
  entries: PlanEntryDetail[];
  /** Absent (Go `*Progress`, omitempty) when the progress rollup fails. */
  progress?: PlanProgress;
}
