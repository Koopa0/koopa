import type {
  DashboardConceptRow,
  DashboardOverview,
  MasteryStage,
  ObservationSignal,
} from '../../../core/models/learning.model';

/** A struggling concept paired with its latest weakness observation, if any. */
export interface WeaknessRow {
  concept: DashboardConceptRow;
  note: string | null;
}

/** One stage pill on the Mastery overview widget. */
export interface StagePill {
  id: MasteryStage;
  count: number;
}

/** Cap for the weakness widget so one bad week stays scannable. */
const WEAKNESS_ROW_LIMIT = 8;

/** Badge classes per real mastery stage (struggling → developing → solid). */
export const STAGE_BADGE_CLASS: Record<MasteryStage, string> = {
  struggling: 'bg-error-bg text-error',
  developing: 'bg-info-bg text-info',
  solid: 'bg-success-bg text-success',
};

/** Header text color per observation signal. */
export const SIGNAL_CLASS: Record<ObservationSignal, string> = {
  weakness: 'text-error',
  mastery: 'text-success',
  improvement: 'text-brand',
};

/** Counts concept rows per mastery stage, in progression order. */
export function computeStagePills(rows: DashboardConceptRow[]): StagePill[] {
  const stages: readonly MasteryStage[] = ['struggling', 'developing', 'solid'];
  return stages.map((id) => ({
    id,
    count: rows.filter((r) => r.mastery_stage === id).length,
  }));
}

/** Mean of per-concept mastery_value, as a 0–100 percentage. */
export function computeAvgMasteryPercent(rows: DashboardConceptRow[]): number {
  if (rows.length === 0) return 0;
  const sum = rows.reduce((acc, r) => acc + r.mastery_value, 0);
  return Math.round((sum / rows.length) * 100);
}

/** Concept rows sorted strongest-mastery first. */
export function sortByMastery(
  rows: DashboardConceptRow[],
): DashboardConceptRow[] {
  return [...rows].sort((a, b) => b.mastery_value - a.mastery_value);
}

/** Struggling concepts, weakest first, with their latest weakness note. */
export function deriveWeaknesses(
  v: DashboardOverview | undefined,
): WeaknessRow[] {
  if (!v) return [];
  return v.concepts.rows
    .filter((r) => r.mastery_stage === 'struggling')
    .sort((a, b) => a.mastery_value - b.mastery_value)
    .slice(0, WEAKNESS_ROW_LIMIT)
    .map((concept) => ({
      concept,
      note:
        v.recent_observations.find(
          (o) => o.signal === 'weakness' && o.concept_slug === concept.slug,
        )?.body ?? null,
    }));
}
