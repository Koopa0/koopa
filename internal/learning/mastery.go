package learning

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/retrieval"
)

// MasteryMapResult is the response for the mastery_map tool.
type MasteryMapResult struct {
	Patterns   []PatternMastery `json:"patterns"`
	PeriodDays int              `json:"period_days"`
}

// PatternMastery is the mastery assessment for a single algorithmic pattern.
type PatternMastery struct {
	Pattern                string               `json:"pattern"`
	Stage                  string               `json:"stage"`
	StageReason            string               `json:"stage_reason"`
	ProblemsSolved         int                  `json:"problems_solved"`
	ResultDistribution     map[string]int       `json:"result_distribution"`
	DifficultyDistribution map[string]int       `json:"difficulty_distribution"`
	LastPracticed          string               `json:"last_practiced"`
	ConceptMastery         map[string]int       `json:"concept_mastery"`
	WeakConcepts           []WeakConcept        `json:"weak_concepts"`
	UnexploredApproaches   []UnexploredApproach `json:"unexplored_approaches"`
	WeaknessTags           []WeaknessTagSummary `json:"weakness_tags"`
	ImprovementTags        []WeaknessTagSummary `json:"improvement_tags"`
	VariationCoverage      VariationCoverage    `json:"variation_coverage"`
	RegressionSignal       *RegressionSignal    `json:"regression_signal"`
	StageSignals           StageSignals         `json:"stage_signals"`
}

// WeakConcept is a concept where mastery is guided or told.
type WeakConcept struct {
	Concept      string `json:"concept"`
	Mastery      string `json:"mastery"`
	FromProblem  int    `json:"from_problem"`
	CoachingHint string `json:"coaching_hint,omitempty"`
	Date         string `json:"date"`
}

// UnexploredApproach is an alternative approach that hasn't been explored.
type UnexploredApproach struct {
	Name          string `json:"name"`
	ProblemNumber int    `json:"problem_number"`
}

// WeaknessTagSummary is a weakness or improvement tag with count and trend.
type WeaknessTagSummary struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
	Trend string `json:"trend"`
}

// VariationCoverage tracks which problems have been attempted and which follow-ups exist.
type VariationCoverage struct {
	Attempted      []int          `json:"attempted"`
	KnownFollowUps []FollowUpLink `json:"known_follow_ups"`
}

// FollowUpLink is a problem linked via variation_links that hasn't been attempted.
type FollowUpLink struct {
	ProblemNumber int    `json:"problem_number"`
	Relationship  string `json:"relationship"`
	FromProblem   int    `json:"from_problem"`
}

// RegressionSignal indicates performance regression in a pattern.
type RegressionSignal struct {
	FSRSRegressions []FSRSRegression `json:"fsrs_regressions,omitempty"`
	ResultTrend     string           `json:"result_trend,omitempty"`
}

// FSRSRegression is a single FSRS card regression event.
type FSRSRegression struct {
	Slug       string `json:"slug"`
	Title      string `json:"title"`
	Tag        string `json:"tag,omitempty"`
	ReviewedAt string `json:"reviewed_at"`
}

// StageSignals contains the raw numeric signals used for stage computation.
type StageSignals struct {
	ProblemsSolved       int     `json:"problems_solved"`
	ACIndependentRate    float64 `json:"ac_independent_rate"`
	RecentGuidedRatio    float64 `json:"recent_guided_ratio"`
	HasMediumPlus        bool    `json:"has_medium_plus"`
	WeaknessTrendDecline bool    `json:"weakness_trend_decline"`
}

// DifficultyTags maps difficulty tag strings to true for classification.
var DifficultyTags = map[string]bool{
	"easy": true, "medium": true, "hard": true,
}

// stagePriority orders patterns by urgency for sorting: struggling first, solid last.
var stagePriority = map[string]int{
	"struggling": 0, "developing": 1, "unexplored": 2, "solid": 3,
}

// leetcodeMetadata is the parsed ai_metadata structure for LeetCode TILs.
type leetcodeMetadata struct {
	ProblemNumber         int                     `json:"problem_number"`
	Pattern               string                  `json:"pattern"`
	ConceptBreakdown      []ConceptBreakdownEntry `json:"concept_breakdown"`
	AlternativeApproaches []AlternativeApproach   `json:"alternative_approaches"`
	VariationLinks        []VariationLink         `json:"variation_links"`
	SolveContext          *SolveContext           `json:"solve_context"`
	WeaknessObservations  []WeaknessObservation   `json:"weakness_observations"`
}

// patternData accumulates data for a single pattern during mastery computation.
type patternData struct {
	entries    []entryData
	lastDate   time.Time
	results    map[string]int
	difficulty map[string]int
}

// entryData is a parsed TIL entry with extracted metadata.
type entryData struct {
	slug      string
	title     string
	tags      []string
	createdAt time.Time
	meta      leetcodeMetadata
}

// groupByPattern groups entries into per-topic patternData and tracks attempted problem numbers.
func groupByPattern(entries []content.RichTagEntry, patterns []string) (byPattern map[string]*patternData, attempted map[int]bool) {
	patternFilter := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		patternFilter[p] = true
	}

	byPattern = make(map[string]*patternData)
	attempted = make(map[int]bool)

	for i := range entries {
		ed := parseEntryData(&entries[i])
		if ed.meta.ProblemNumber > 0 {
			attempted[ed.meta.ProblemNumber] = true
		}
		addEntryToPatterns(&ed, byPattern, patternFilter)
	}
	return byPattern, attempted
}

func addEntryToPatterns(ed *entryData, patternsMap map[string]*patternData, filter map[string]bool) {
	for _, tag := range ed.tags {
		if !TopicTags[tag] {
			continue
		}
		if len(filter) > 0 && !filter[tag] {
			continue
		}
		pd, ok := patternsMap[tag]
		if !ok {
			pd = &patternData{
				results:    make(map[string]int),
				difficulty: make(map[string]int),
			}
			patternsMap[tag] = pd
		}
		pd.entries = append(pd.entries, *ed)
		if ed.createdAt.After(pd.lastDate) {
			pd.lastDate = ed.createdAt
		}
		for _, t := range ed.tags {
			if ResultTags[t] {
				pd.results[t]++
			}
			if DifficultyTags[t] {
				pd.difficulty[t]++
			}
		}
	}
}

func indexRegressions(regressions []retrieval.RegressionCard) map[string][]retrieval.RegressionCard {
	m := make(map[string][]retrieval.RegressionCard)
	for _, r := range regressions {
		m[r.Slug] = append(m[r.Slug], r)
	}
	return m
}

// MasteryMap computes per-pattern mastery assessment from TIL entries and FSRS data.
func MasteryMap(entries []content.RichTagEntry, regressions []retrieval.RegressionCard, patterns []string, days int) MasteryMapResult {
	patternsMap, attemptedProblems := groupByPattern(entries, patterns)

	regressionsBySlug := indexRegressions(regressions)

	result := make([]PatternMastery, 0, len(patternsMap))
	for pattern, pd := range patternsMap {
		pm := buildPatternMastery(pattern, pd, attemptedProblems, regressionsBySlug)
		result = append(result, pm)
	}

	// stagePriority orders patterns by urgency: struggling first, solid last.
	slices.SortFunc(result, func(a, b PatternMastery) int {
		pa, pb := stagePriority[a.Stage], stagePriority[b.Stage]
		if pa != pb {
			return pa - pb
		}
		return b.ProblemsSolved - a.ProblemsSolved
	})

	return MasteryMapResult{
		Patterns:   result,
		PeriodDays: days,
	}
}

// entryAggregator accumulates per-entry data during pattern mastery computation.
type entryAggregator struct {
	conceptMastery   map[string]int
	weakConcepts     []WeakConcept
	unexplored       []UnexploredApproach
	attempted        []int
	followUps        []FollowUpLink
	weaknessCount    map[string]int
	improvementCount map[string]int
}

func newEntryAggregator() *entryAggregator {
	return &entryAggregator{
		conceptMastery:   make(map[string]int),
		weaknessCount:    make(map[string]int),
		improvementCount: make(map[string]int),
	}
}

func (a *entryAggregator) addEntry(ed *entryData, attemptedGlobal map[int]bool) {
	for _, cb := range ed.meta.ConceptBreakdown {
		a.conceptMastery[cb.Mastery]++
		if cb.Mastery == "guided" || cb.Mastery == "told" {
			a.weakConcepts = append(a.weakConcepts, WeakConcept{
				Concept:      cb.Concept,
				Mastery:      cb.Mastery,
				FromProblem:  ed.meta.ProblemNumber,
				CoachingHint: cb.CoachingHint,
				Date:         ed.createdAt.Format(time.DateOnly),
			})
		}
	}
	for _, aa := range ed.meta.AlternativeApproaches {
		if !aa.Explored {
			a.unexplored = append(a.unexplored, UnexploredApproach{
				Name:          aa.Name,
				ProblemNumber: ed.meta.ProblemNumber,
			})
		}
	}
	if ed.meta.ProblemNumber > 0 {
		a.attempted = append(a.attempted, ed.meta.ProblemNumber)
	}
	for _, vl := range ed.meta.VariationLinks {
		if !attemptedGlobal[vl.ProblemNumber] {
			a.followUps = append(a.followUps, FollowUpLink{
				ProblemNumber: vl.ProblemNumber,
				Relationship:  vl.Relationship,
				FromProblem:   ed.meta.ProblemNumber,
			})
		}
	}
	for _, t := range ed.tags {
		if strings.HasPrefix(t, "weakness:") {
			a.weaknessCount[t]++
		}
		if strings.HasPrefix(t, "improvement:") {
			a.improvementCount[t]++
		}
	}
}

func buildPatternMastery(pattern string, pd *patternData, attempted map[int]bool, regressionsBySlug map[string][]retrieval.RegressionCard) PatternMastery {
	agg := newEntryAggregator()
	for i := range pd.entries {
		agg.addEntry(&pd.entries[i], attempted)
	}

	slices.SortFunc(agg.weakConcepts, func(a, b WeakConcept) int {
		return strings.Compare(b.Date, a.Date)
	})
	slices.Sort(agg.attempted)

	pm := PatternMastery{
		Pattern:                pattern,
		ProblemsSolved:         len(pd.entries),
		ResultDistribution:     pd.results,
		DifficultyDistribution: pd.difficulty,
		LastPracticed:          pd.lastDate.Format(time.DateOnly),
		ConceptMastery:         agg.conceptMastery,
		WeakConcepts:           agg.weakConcepts,
		UnexploredApproaches:   agg.unexplored,
		VariationCoverage: VariationCoverage{
			Attempted:      slices.Compact(agg.attempted),
			KnownFollowUps: agg.followUps,
		},
		WeaknessTags:     buildTagSummaries(agg.weaknessCount, pd.entries),
		ImprovementTags:  buildTagSummaries(agg.improvementCount, pd.entries),
		RegressionSignal: detectRegression(pd, regressionsBySlug),
	}

	signals := computeStageSignals(pd, pm.ConceptMastery)
	pm.Stage, pm.StageReason = computeStage(signals, pm.WeaknessTags)
	for _, wt := range pm.WeaknessTags {
		if wt.Trend == "declining" {
			signals.WeaknessTrendDecline = true
			break
		}
	}
	pm.StageSignals = signals

	return pm
}

func buildTagSummaries(counts map[string]int, entries []entryData) []WeaknessTagSummary {
	summaries := make([]WeaknessTagSummary, 0, len(counts))
	for tag, count := range counts {
		trend := computeTagTrend(tag, entries)
		summaries = append(summaries, WeaknessTagSummary{
			Tag:   tag,
			Count: count,
			Trend: trend,
		})
	}
	slices.SortFunc(summaries, func(a, b WeaknessTagSummary) int {
		return b.Count - a.Count
	})
	return summaries
}

func computeTagTrend(tag string, entries []entryData) string {
	// Simple trend: look at result tags in chronological order for entries with this tag.
	var results []string
	for i := range entries {
		hasTag := false
		var result string
		for _, t := range entries[i].tags {
			if t == tag {
				hasTag = true
			}
			if ResultTags[t] {
				result = t
			}
		}
		if hasTag && result != "" {
			results = append(results, result)
		}
	}
	if len(results) < 3 {
		return "insufficient-data"
	}
	window := results
	if len(window) > 5 {
		window = window[len(window)-5:]
	}
	good, bad := 0, 0
	for _, r := range window {
		switch r {
		case "ac-independent":
			good++
		case "ac-after-solution", "incomplete":
			bad++
		}
	}
	switch {
	case good > bad+1:
		return "improving"
	case bad > good+1:
		return "declining"
	default:
		return "stable"
	}
}

func detectRegression(pd *patternData, regressionsBySlug map[string][]retrieval.RegressionCard) *RegressionSignal {
	var fsrsRegs []FSRSRegression
	for i := range pd.entries {
		for _, r := range regressionsBySlug[pd.entries[i].slug] {
			tag := r.Tag
			fsrsRegs = append(fsrsRegs, FSRSRegression{
				Slug:       r.Slug,
				Title:      r.Title,
				Tag:        tag,
				ReviewedAt: r.ReviewedAt.Format(time.DateOnly),
			})
		}
	}

	// Secondary: compare recent 3 vs previous 3 result tags.
	resultTrend := ""
	if len(pd.entries) >= 6 {
		// Entries are in DB order (DESC), so index 0 is most recent.
		recentAC := countACIndependent(pd.entries[:3])
		previousAC := countACIndependent(pd.entries[3:6])
		if recentAC < previousAC {
			resultTrend = fmt.Sprintf("recent 3 problems: %d ac-independent vs previous 3: %d", recentAC, previousAC)
		}
	}

	if len(fsrsRegs) == 0 && resultTrend == "" {
		return nil
	}
	return &RegressionSignal{
		FSRSRegressions: fsrsRegs,
		ResultTrend:     resultTrend,
	}
}

func countACIndependent(entries []entryData) int {
	count := 0
	for i := range entries {
		for _, t := range entries[i].tags {
			if t == "ac-independent" {
				count++
				break
			}
		}
	}
	return count
}

func computeStageSignals(pd *patternData, conceptMastery map[string]int) StageSignals {
	total := len(pd.entries)
	acIndependent := pd.results["ac-independent"]
	var acRate float64
	if total > 0 {
		acRate = float64(acIndependent) / float64(total)
	}

	guided := conceptMastery["guided"] + conceptMastery["told"]
	independent := conceptMastery["independent"] + conceptMastery["independent_after_hint"]
	totalConcepts := guided + independent + conceptMastery["not_explored"]
	var guidedRatio float64
	if totalConcepts > 0 {
		guidedRatio = float64(guided) / float64(totalConcepts)
	}

	hasMediumPlus := pd.difficulty["medium"] > 0 || pd.difficulty["hard"] > 0

	return StageSignals{
		ProblemsSolved:       total,
		ACIndependentRate:    acRate,
		RecentGuidedRatio:    guidedRatio,
		HasMediumPlus:        hasMediumPlus,
		WeaknessTrendDecline: false, // set by caller after stage computation
	}
}

func hasDeclineTrend(tags []WeaknessTagSummary) bool {
	for _, wt := range tags {
		if wt.Trend == "declining" {
			return true
		}
	}
	return false
}

func isSolid(s StageSignals, decline bool) bool {
	return s.ProblemsSolved >= 4 && s.ACIndependentRate >= 0.75 &&
		s.RecentGuidedRatio < 0.2 && s.HasMediumPlus && !decline
}

func isDeveloping(s StageSignals, decline bool) bool {
	return s.ProblemsSolved >= 3 && s.ACIndependentRate >= 0.5 && !decline
}

func computeStage(signals StageSignals, weaknessTags []WeaknessTagSummary) (stage, reason string) {
	decline := hasDeclineTrend(weaknessTags)
	n := signals.ProblemsSolved
	base := fmt.Sprintf("%d problems, %.0f%% ac-independent", n, signals.ACIndependentRate*100)

	switch {
	case n <= 1:
		return "unexplored", fmt.Sprintf("%d problem solved — not enough data", n)
	case isSolid(signals, decline):
		return "solid", base + ", guided concepts <20%, includes medium+ difficulty"
	case isDeveloping(signals, decline):
		reason := base
		if signals.RecentGuidedRatio > 0.3 {
			reason += ", but >30% guided concepts in recent sessions"
		}
		if !signals.HasMediumPlus {
			reason += ", no medium+ difficulty attempted"
		}
		return "developing", reason
	default:
		reason := base
		if signals.RecentGuidedRatio > 0.5 {
			reason += ", majority of concepts guided/told"
		}
		if decline {
			reason += ", declining weakness trend"
		}
		return "struggling", reason
	}
}

func parseEntryData(e *content.RichTagEntry) entryData {
	ed := entryData{
		slug:      e.Slug,
		title:     e.Title,
		tags:      e.Tags,
		createdAt: e.CreatedAt,
	}
	if len(e.AIMetadata) > 0 {
		// best-effort parse — ignore errors for old-format metadata
		_ = json.Unmarshal(e.AIMetadata, &ed.meta)
	}
	return ed
}

// --- Concept Gaps ---

// ConceptGapsResult is the response for the concept_gaps tool.
type ConceptGapsResult struct {
	SystemicGaps    []SystemicGap    `json:"systemic_gaps"`
	CoachingHistory []CoachingRecord `json:"coaching_history"`
	PeriodDays      int              `json:"period_days"`
}

// SystemicGap is a concept that appears as guided/told across multiple TILs.
type SystemicGap struct {
	Concept     string          `json:"concept"`
	Occurrences []GapOccurrence `json:"occurrences"`
	Count       int             `json:"count"`
	Suggestion  string          `json:"suggestion"`
}

// GapOccurrence is a single occurrence of a weak concept.
type GapOccurrence struct {
	ProblemNumber int    `json:"problem_number"`
	Pattern       string `json:"pattern"`
	Mastery       string `json:"mastery"`
	Date          string `json:"date"`
}

// CoachingRecord is a coaching hint given during a session.
type CoachingRecord struct {
	Concept       string `json:"concept"`
	CoachingHint  string `json:"coaching_hint"`
	ProblemNumber int    `json:"problem_number"`
	Date          string `json:"date"`
	Mastery       string `json:"mastery"`
}

// ConceptGaps scans all concept_breakdowns and finds concepts that appear as
// guided/told across multiple TILs. Groups by exact concept string (normalized).
func ConceptGaps(entries []content.RichTagEntry, masteryFilter []string, days int) ConceptGapsResult {
	// Default filter: guided + told.
	filterSet := make(map[string]bool, len(masteryFilter))
	if len(masteryFilter) == 0 {
		filterSet["guided"] = true
		filterSet["told"] = true
	} else {
		for _, m := range masteryFilter {
			filterSet[m] = true
		}
	}

	// concept string -> occurrences
	gapMap := make(map[string][]GapOccurrence)
	var coachingHistory []CoachingRecord

	for i := range entries {
		ed := parseEntryData(&entries[i])
		pattern := extractPrimaryPattern(ed.tags)

		for _, cb := range ed.meta.ConceptBreakdown {
			// Collect coaching hints regardless of mastery filter.
			if cb.CoachingHint != "" {
				coachingHistory = append(coachingHistory, CoachingRecord{
					Concept:       cb.Concept,
					CoachingHint:  cb.CoachingHint,
					ProblemNumber: ed.meta.ProblemNumber,
					Date:          ed.createdAt.Format(time.DateOnly),
					Mastery:       cb.Mastery,
				})
			}

			if !filterSet[cb.Mastery] {
				continue
			}

			key := strings.ToLower(strings.TrimSpace(cb.Concept))
			gapMap[key] = append(gapMap[key], GapOccurrence{
				ProblemNumber: ed.meta.ProblemNumber,
				Pattern:       pattern,
				Mastery:       cb.Mastery,
				Date:          ed.createdAt.Format(time.DateOnly),
			})
		}
	}

	// Filter: only concepts appearing across 2+ TILs.
	var gaps []SystemicGap
	for concept, occs := range gapMap {
		if len(occs) < 2 {
			continue
		}
		gaps = append(gaps, SystemicGap{
			Concept:     concept,
			Occurrences: occs,
			Count:       len(occs),
			Suggestion:  fmt.Sprintf("this concept appears as guided/told across %d problems — may need dedicated practice", len(occs)),
		})
	}
	// Sort by count descending.
	slices.SortFunc(gaps, func(a, b SystemicGap) int {
		return b.Count - a.Count
	})

	// Sort coaching history by recency (most recent first).
	slices.SortFunc(coachingHistory, func(a, b CoachingRecord) int {
		return strings.Compare(b.Date, a.Date)
	})

	return ConceptGapsResult{
		SystemicGaps:    gaps,
		CoachingHistory: coachingHistory,
		PeriodDays:      days,
	}
}

// extractPrimaryPattern returns the first topic tag found in a tag list.
func extractPrimaryPattern(tags []string) string {
	for _, t := range tags {
		if TopicTags[t] {
			return t
		}
	}
	return ""
}

// --- Variation Map ---

// VariationMapResult is the response for the variation_map tool.
type VariationMapResult struct {
	Clusters         []VariationCluster `json:"clusters"`
	IsolatedProblems []IsolatedProblem  `json:"isolated_problems"`
	PeriodDays       int                `json:"period_days"`
}

// VariationCluster groups a problem with its linked variations.
type VariationCluster struct {
	AnchorProblem AnchorProblem   `json:"anchor_problem"`
	Variations    []VariationNode `json:"variations"`
}

// AnchorProblem is the center of a variation cluster.
type AnchorProblem struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Result string `json:"result"`
}

// VariationNode is a linked problem in a variation cluster.
type VariationNode struct {
	ProblemNumber int    `json:"problem_number"`
	Relationship  string `json:"relationship"`
	Attempted     bool   `json:"attempted"`
	Notes         string `json:"notes,omitempty"`
}

// IsolatedProblem is a problem with no variation links.
type IsolatedProblem struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Result string `json:"result"`
}

type problemInfo struct {
	title  string
	result string
	links  []VariationLink
}

func hasTag(tags []string, target string) bool {
	for _, t := range tags {
		if t == target {
			return true
		}
	}
	return false
}

func collectProblems(entries []content.RichTagEntry, patternFilter string) (attempted map[int]bool, problems map[int]*problemInfo) {
	attempted = make(map[int]bool)
	problems = make(map[int]*problemInfo)
	for i := range entries {
		ed := parseEntryData(&entries[i])
		if ed.meta.ProblemNumber == 0 {
			continue
		}
		if patternFilter != "" && !hasTag(ed.tags, patternFilter) {
			continue
		}
		attempted[ed.meta.ProblemNumber] = true
		problems[ed.meta.ProblemNumber] = &problemInfo{
			title:  ed.title,
			result: extractResultTag(ed.tags),
			links:  ed.meta.VariationLinks,
		}
	}
	return attempted, problems
}

func buildClusters(problems map[int]*problemInfo, attempted map[int]bool, includeUnattempted bool) (clusters []VariationCluster, clustered map[int]bool) {
	clustered = make(map[int]bool)

	for num, info := range problems {
		if len(info.links) == 0 {
			continue
		}
		clustered[num] = true

		var variations []VariationNode
		for _, vl := range info.links {
			isAttempted := attempted[vl.ProblemNumber]
			if !includeUnattempted && !isAttempted {
				continue
			}
			clustered[vl.ProblemNumber] = true
			variations = append(variations, VariationNode{
				ProblemNumber: vl.ProblemNumber,
				Relationship:  vl.Relationship,
				Attempted:     isAttempted,
				Notes:         vl.Notes,
			})
		}
		clusters = append(clusters, VariationCluster{
			AnchorProblem: AnchorProblem{Number: num, Title: info.title, Result: info.result},
			Variations:    variations,
		})
	}
	return clusters, clustered
}

// VariationMap builds a problem relationship graph from variation_links metadata.
func VariationMap(entries []content.RichTagEntry, patternFilter string, includeUnattempted bool, days int) VariationMapResult {
	attempted, problems := collectProblems(entries, patternFilter)
	clusters, clustered := buildClusters(problems, attempted, includeUnattempted)

	// Sort clusters by anchor problem number for deterministic output.
	slices.SortFunc(clusters, func(a, b VariationCluster) int {
		return a.AnchorProblem.Number - b.AnchorProblem.Number
	})

	// Isolated problems: attempted but not part of any cluster.
	var isolated []IsolatedProblem
	for num, info := range problems {
		if clustered[num] {
			continue
		}
		isolated = append(isolated, IsolatedProblem{
			Number: num,
			Title:  info.title,
			Result: info.result,
		})
	}
	slices.SortFunc(isolated, func(a, b IsolatedProblem) int {
		return a.Number - b.Number
	})

	return VariationMapResult{
		Clusters:         clusters,
		IsolatedProblems: isolated,
		PeriodDays:       days,
	}
}
