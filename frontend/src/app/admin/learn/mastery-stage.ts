// Port of internal/mcp/learning.go:492 deriveMasteryStage.
// Rules and thresholds MUST stay in sync with the Go source.
// See also: internal/mcp/learning_unit_test.go for the canonical test cases.

export type MasteryStage = 'developing' | 'solid' | 'struggling';

const MIN_OBSERVATIONS_FOR_VERDICT = 3;

export function deriveMasteryStage(
  weakness: number,
  improvement: number,
  mastery: number,
): MasteryStage {
  const total = weakness + improvement + mastery;
  if (total < MIN_OBSERVATIONS_FOR_VERDICT) return 'developing';
  if (mastery >= 2 && mastery >= 2 * weakness) return 'solid';
  if (weakness >= 2 && weakness > mastery) return 'struggling';
  return 'developing';
}
