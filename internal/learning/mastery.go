package learning

// MasteryStage is a summary of a concept's observation history derived from
// filtered signal counts. The heuristic in DeriveMasteryStage decides which
// stage applies.
type MasteryStage string

// Mastery stages, roughly ordered from least to most proficient.
const (
	StageStruggling MasteryStage = "struggling" // weakness dominates with enough observations to trust the signal
	StageDeveloping MasteryStage = "developing" // mixed signal, OR insufficient observations to label
	StageSolid      MasteryStage = "solid"      // mastery dominates with enough observations to trust the signal
)

// MinObservationsForVerdict is the floor below which a concept always
// reports "developing" regardless of signal mix. Without it, a single
// observation could permanently label a concept (1 weakness → struggling
// forever, 1 mastery → solid forever) which destroys the signal.
//
// Three is the smallest number that lets the 2:1 ratio rules below ever
// fire — and it matches the audit's intuition that "two data points is
// noise, three is the start of a pattern."
const MinObservationsForVerdict = 3

// DeriveMasteryStage applies the mastery-stage heuristic to filtered signal
// counts within the dashboard window.
//
// Rules, in priority order:
//  1. fewer than MinObservationsForVerdict (3) total observations →
//     developing. The single most important rule. It prevents one stray
//     observation from permanently labelling a concept.
//  2. mastery >= 2 AND mastery >= 2 * weakness → solid. Needs both
//     absolute count (≥2 mastery) and dominance ratio (mastery double
//     weakness). A single mastery against zero weakness is technically
//     a 2:1 ratio but is still 1 observation against 0, so the absolute
//     floor catches it.
//  3. weakness >= 2 AND weakness > mastery → struggling. Same idea
//     mirrored: need at least 2 weakness signals AND weakness must
//     outnumber mastery (not just tie).
//  4. anything else → developing. Includes mixed signal (4M+3W → 4
//     mastery is not double 3 weakness, 3 weakness is not greater than 4
//     mastery, so neither solid nor struggling fires) and improvement-led
//     progressions (a concept with all improvements lands here too).
//
// CRITICAL: the (weakness, improvement, mastery) counts MUST be those
// returned by ConceptMastery under the SAME confidence_filter as the
// dashboard request. Looking at unfiltered totals would let a low-confidence
// observation "unlock" a stage from below the floor — re-creating the
// half-gate the confidence column was designed to remove.
func DeriveMasteryStage(weakness, improvement, mastery int64) MasteryStage {
	total := weakness + improvement + mastery
	switch {
	case total < MinObservationsForVerdict:
		return StageDeveloping
	case mastery >= 2 && mastery >= 2*weakness:
		return StageSolid
	case weakness >= 2 && weakness > mastery:
		return StageStruggling
	default:
		return StageDeveloping
	}
}

// DomainMastery is a per-domain aggregation of concept mastery stages.
type DomainMastery struct {
	Domain             string `json:"domain"`
	ConceptsTotal      int    `json:"concepts_total"`
	ConceptsMastered   int    `json:"concepts_mastered"`
	ConceptsWeak       int    `json:"concepts_weak"`
	ConceptsDeveloping int    `json:"concepts_developing"`
}

// AggregateMasteryByDomain groups per-concept mastery rows by domain and
// counts how many concepts fall into each mastery stage.
func AggregateMasteryByDomain(rows []ConceptMasteryRow) []DomainMastery {
	type counts struct {
		total, mastered, weak, developing int
	}
	m := map[string]*counts{}
	var order []string

	for i := range rows {
		r := &rows[i]
		c, ok := m[r.Domain]
		if !ok {
			c = &counts{}
			m[r.Domain] = c
			order = append(order, r.Domain)
		}
		c.total++
		stage := DeriveMasteryStage(r.WeaknessCount, r.ImprovementCount, r.MasteryCount)
		switch stage {
		case StageSolid:
			c.mastered++
		case StageStruggling:
			c.weak++
		case StageDeveloping:
			c.developing++
		}
	}

	result := make([]DomainMastery, len(order))
	for i, domain := range order {
		c := m[domain]
		result[i] = DomainMastery{
			Domain:             domain,
			ConceptsTotal:      c.total,
			ConceptsMastered:   c.mastered,
			ConceptsWeak:       c.weak,
			ConceptsDeveloping: c.developing,
		}
	}
	return result
}
