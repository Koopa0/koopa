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
  next_due: string | null;
}

export interface DashboardDueItem {
  card_id: string;
  target: { id: string; title: string };
  domain: LearningDomain;
  retention: number;
  last_reviewed_at: string | null;
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
  concepts: {
    count_total: number;
    counts_by_domain: Record<string, number>;
    rows: DashboardConceptRow[];
  };
  due_today: {
    count: number;
    items: DashboardDueItem[];
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
  next_due_target: {
    id: string;
    title: string;
    due_at: string | null;
  } | null;
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

export interface ConceptProfile extends ConceptRow {
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

export type PlanEntryStatus =
  | 'pending'
  | 'completed'
  | 'skipped'
  | 'substituted';

export type PlanStatus =
  | 'draft'
  | 'active'
  | 'paused'
  | 'completed'
  | 'abandoned';

export interface PlanRow {
  id: string;
  title: string;
  status: PlanStatus;
  goal_id: string | null;
  summary: {
    total: number;
    completed: number;
    skipped: number;
    substituted: number;
  };
  updated_at: string;
}

export interface PlanEntry {
  id: string;
  position: number;
  status: PlanEntryStatus;
  target: { id: string; title: string };
  completed_at?: string | null;
  completed_by_attempt_id?: string | null;
  reason?: string | null;
}

export interface PlanDetail {
  id: string;
  title: string;
  status: PlanStatus;
  goal_id: string | null;
  entries: PlanEntry[];
  summary: {
    total: number;
    completed: number;
    skipped: number;
    substituted: number;
  };
}
