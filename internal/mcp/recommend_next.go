package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/learning"
)

// Constants for recommend_next_target orchestration. All are intentionally
// conservative — the recommender is supposed to suggest a handful of
// strong candidates, not exhaust the variation graph.
const (
	recommendDefaultCount    = 3
	recommendMaxCount        = 10
	recommendWeaknessesTopN  = 5  // how many weakness concepts feed candidate generation
	recommendAttemptsPerConc = 20 // attempts per concept used to identify anchors
	recommendVariationsLimit = 100
	recommendWindowDays      = 30
)

// RecommendNextTargetInput is the input for the recommend_next_target tool.
// SessionID is required so the interleaving filter has a scope ("recent
// patterns in THIS session"). Domain defaults to the session's own domain;
// Count defaults to 3 and clamps to [1, 10].
type RecommendNextTargetInput struct {
	SessionID       string   `json:"session_id" jsonschema:"required" jsonschema_description:"Active session UUID the recommendation is scoped to. The interleaving filter uses this session's attempts as the 'recent patterns' set."`
	Domain          *string  `json:"domain,omitempty" jsonschema_description:"Override domain filter. Defaults to the session's domain; override only to recommend within a different subdomain of the same practice track."`
	Count           FlexInt  `json:"count,omitempty" jsonschema_description:"Number of candidates to return, 1..10. Default 3."`
	ExcludePatterns []string `json:"exclude_patterns,omitempty" jsonschema_description:"Explicit patterns to reject from candidates (in addition to auto-detected recent patterns). Use when the coach wants to avoid a specific pattern beyond what this session's attempts imply."`
}

// Candidate is a single recommended target with full provenance so the
// coach can explain the choice to the user. Reason is pre-rendered as a
// natural-language sentence.
type Candidate struct {
	TargetID       uuid.UUID  `json:"target_id"`
	Title          string     `json:"title"`
	ExternalID     *string    `json:"external_id,omitempty"`
	Difficulty     *string    `json:"difficulty,omitempty"`
	SourceConcept  string     `json:"source_concept"`
	SourceSeverity string     `json:"source_severity"`
	RelationType   string     `json:"relation_type,omitempty"`
	AnchorTargetID *uuid.UUID `json:"anchor_target_id,omitempty"`
	AnchorTitle    string     `json:"anchor_title,omitempty"`
	Reason         string     `json:"reason"`
}

// RecommendNextTargetOutput carries the ranked candidates plus enough
// observability to debug empty results (RecentPatterns) and communicate
// graceful degradation (EmptyReason).
type RecommendNextTargetOutput struct {
	Candidates     []Candidate `json:"candidates"`
	RecentPatterns []string    `json:"recent_patterns,omitempty"`
	EmptyReason    string      `json:"empty_reason,omitempty"`
}

// recommendAllowedRelations is the closed set of variation types the
// recommender will surface. prerequisite and easier_variant are
// deliberately excluded — recommend_next_target means "move forward",
// not "fill in a gap or ease up". A separate tool would own the
// backfill direction if it ever becomes a need.
var recommendAllowedRelations = map[string]int{
	string(learning.RelationHarderVariant):    0, // highest priority
	string(learning.RelationFollowUp):         1,
	string(learning.RelationSamePattern):      2,
	string(learning.RelationSimilarStructure): 3,
}

// severityRank orders candidates so critical weaknesses surface before
// moderate/minor. Anything not listed (including empty severity) ranks
// lowest — we never want to push an unlabelled concept ahead of a
// critical one.
var severityRank = map[string]int{
	"critical": 0,
	"moderate": 1,
	"minor":    2,
}

func (s *Server) recommendNextTarget(ctx context.Context, _ *mcp.CallToolRequest, input RecommendNextTargetInput) (*mcp.CallToolResult, RecommendNextTargetOutput, error) {
	sessionID, err := uuid.Parse(input.SessionID)
	if err != nil {
		return nil, RecommendNextTargetOutput{}, fmt.Errorf("%w: invalid session_id: %w", learning.ErrInvalidInput, err)
	}

	active, err := s.learn.ActiveSession(ctx)
	if err != nil {
		return nil, RecommendNextTargetOutput{}, fmt.Errorf("no active session: %w", err)
	}
	if active.ID != sessionID {
		return nil, RecommendNextTargetOutput{}, fmt.Errorf("%w: session %s is not the active session", learning.ErrInvalidInput, sessionID)
	}

	domain := active.Domain
	if input.Domain != nil && *input.Domain != "" {
		domain = *input.Domain
	}
	count := clamp(int(input.Count), 1, recommendMaxCount, recommendDefaultCount)

	recentPatterns := s.collectRecentPatterns(ctx, sessionID, input.ExcludePatterns)

	// Pull top weakness concepts. If this is empty, the user has no
	// practice-backed weaknesses in window — we can't recommend
	// without weakness signal, so bail with a descriptive reason.
	weaknesses, err := s.learn.WeaknessAnalysis(ctx, &domain, time.Now().AddDate(0, 0, -recommendWindowDays), "high")
	if err != nil {
		return nil, RecommendNextTargetOutput{}, fmt.Errorf("fetching weaknesses: %w", err)
	}
	if len(weaknesses) == 0 {
		return nil, RecommendNextTargetOutput{
			Candidates:     []Candidate{},
			RecentPatterns: recentPatterns,
			EmptyReason:    "no concepts need practice in the 30-day window",
		}, nil
	}

	candidates := s.buildCandidatesFromWeaknesses(ctx, domain, weaknesses, recentPatterns)

	// Soft relaxation: if the interleaving filter wiped every
	// candidate, retry without it so the coach still gets SOMETHING
	// rather than an empty list. The relaxed flag propagates into
	// empty_reason so the caller can note it to the user.
	relaxedFilter := false
	if len(candidates) == 0 && len(recentPatterns) > 0 {
		candidates = s.buildCandidatesFromWeaknesses(ctx, domain, weaknesses, nil)
		relaxedFilter = true
	}

	if len(candidates) == 0 {
		// Multiple paths land here; the previous single-line reason
		// asserted "no untried variations were recorded" which was
		// misleading when the actual cause was "weakness anchors don't
		// match any recorded related_targets" — variations had been
		// recorded but on non-weakness concepts. Spell out every cause
		// so the coach can pick the right remediation.
		const causes = "possible causes: " +
			"(a) weakness concepts have no recorded attempts, so no anchor targets exist; " +
			"(b) anchor targets exist but no learning_target_relations were recorded from them; " +
			"(c) every related target has already been attempted; " +
			"(d) recorded relations connect non-weakness concepts (a variation hung off a concept that did not surface as a weakness)"
		var reason string
		if relaxedFilter {
			reason = "weaknesses exist but no candidate variations passed filters even after relaxing interleaving — " + causes
		} else {
			reason = "weaknesses exist but no candidate variations passed filters — " + causes +
				"; or (e) all candidates shared a pattern with this session's recent attempts (interleaving filter)"
		}
		return nil, RecommendNextTargetOutput{
			Candidates:     []Candidate{},
			RecentPatterns: recentPatterns,
			EmptyReason:    reason,
		}, nil
	}

	rankCandidates(candidates)
	if len(candidates) > count {
		candidates = candidates[:count]
	}

	out := RecommendNextTargetOutput{
		Candidates:     candidates,
		RecentPatterns: recentPatterns,
	}
	if relaxedFilter {
		out.EmptyReason = "relaxed interleaving filter — all first-pass candidates shared a recent pattern from this session"
	}

	s.logger.Info("recommend_next_target",
		"session_id", sessionID, "domain", domain,
		"weaknesses", len(weaknesses), "candidates", len(candidates),
		"recent_patterns", len(recentPatterns), "relaxed", relaxedFilter)

	return nil, out, nil
}

// collectRecentPatterns extracts the `pattern` field from each attempt's
// metadata in the current session. Interleaving filter scope is
// explicitly CURRENT SESSION ONLY — cross-session interleaving is the
// coach's responsibility at session start via the timeline dashboard
// view. Extending the window here would trigger filter decisions against
// patterns from weeks ago, which makes no sense inside a single session.
//
// Missing or malformed metadata.pattern is silently skipped (logged for
// observability — a sustained high miss rate signals the coach is not
// recording pattern on attempts and the filter is effectively dead).
// ExcludePatterns from the caller are appended after dedup.
func (s *Server) collectRecentPatterns(ctx context.Context, sessionID uuid.UUID, explicitExcludes []string) []string {
	attempts, err := s.learn.AttemptsBySession(ctx, sessionID)
	if err != nil {
		s.logger.Warn("recommend_next_target: session attempts lookup failed", "session_id", sessionID, "error", err)
		return explicitExcludes
	}

	seen := map[string]struct{}{}
	patterns := make([]string, 0, len(attempts))
	missingPattern := 0
	for i := range attempts {
		p := extractMetadataPattern(attempts[i].Metadata)
		if p == "" {
			missingPattern++
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		patterns = append(patterns, p)
	}

	for _, p := range explicitExcludes {
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		patterns = append(patterns, p)
	}

	if missingPattern > 0 {
		s.logger.Info("recommend_next_target: attempts missing metadata.pattern",
			"session_id", sessionID, "missing", missingPattern, "total", len(attempts))
	}

	return patterns
}

// extractMetadataPattern pulls the `pattern` string from an attempt's
// JSONB metadata. metadata is free-form; pattern is the single
// convention-level field recommend_next_target relies on. Non-string
// pattern values are treated as missing (the coach wrote something
// non-string and the filter decides to not gate on it — safer than
// stringifying a bool/number).
func extractMetadataPattern(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var holder struct {
		Pattern string `json:"pattern"`
	}
	if err := json.Unmarshal(raw, &holder); err != nil {
		return ""
	}
	return holder.Pattern
}

// buildCandidatesFromWeaknesses walks the weakness list, looks up each
// weakness concept's practiced targets, and fans out into the variation
// graph to find untried related targets. Candidates are deduped by
// target_id (first weakness that surfaces a given target wins) and
// filtered against recentPatterns (interleaving) if non-nil/non-empty.
//
// The walk stops at recommendWeaknessesTopN because the weakness list is
// already severity-ordered; a 6th-ranked weakness is rarely the right
// source for the next problem.
func (s *Server) buildCandidatesFromWeaknesses(ctx context.Context, domain string, weaknesses []learning.WeaknessRow, recentPatterns []string) []Candidate {
	excludeSet := map[string]struct{}{}
	for _, p := range recentPatterns {
		excludeSet[p] = struct{}{}
	}

	topN := recommendWeaknessesTopN
	if len(weaknesses) < topN {
		topN = len(weaknesses)
	}

	seenTargets := map[uuid.UUID]struct{}{}
	candidates := make([]Candidate, 0, topN*2)

	for i := range topN {
		c := s.candidatesForWeakness(ctx, domain, &weaknesses[i], seenTargets, excludeSet)
		candidates = append(candidates, c...)
	}

	return candidates
}

// candidatesForWeakness is the per-weakness body of buildCandidates, factored
// out so the outer loop stays simple. Mutates seenTargets so callers can
// dedupe across weaknesses. Returns whatever candidates this weakness
// surfaced; DB lookup failures log and produce zero results without
// failing the outer walk.
func (s *Server) candidatesForWeakness(
	ctx context.Context,
	domain string,
	w *learning.WeaknessRow,
	seenTargets map[uuid.UUID]struct{},
	excludeSet map[string]struct{},
) []Candidate {
	concept, err := s.learn.ConceptBySlug(ctx, w.Domain, w.ConceptSlug)
	if err != nil {
		s.logger.Warn("recommend_next_target: concept lookup failed", "slug", w.ConceptSlug, "error", err)
		return nil
	}
	attempts, err := s.learn.AttemptsByConcept(ctx, concept.ID, recommendAttemptsPerConc)
	if err != nil {
		s.logger.Warn("recommend_next_target: attempts-by-concept lookup failed", "concept_id", concept.ID, "error", err)
		return nil
	}
	if len(attempts) == 0 {
		return nil
	}
	variations, err := s.learn.TargetVariations(ctx, &domain, recommendVariationsLimit)
	if err != nil {
		s.logger.Warn("recommend_next_target: variations lookup failed", "domain", domain, "error", err)
		return nil
	}

	anchorIDs := attemptTargetSet(attempts)
	severity := dominantSeverity(w)

	out := make([]Candidate, 0, len(variations))
	for r := range variations {
		rel := &variations[r]
		if !s.acceptVariation(ctx, rel, anchorIDs, seenTargets, excludeSet) {
			continue
		}
		seenTargets[rel.RelatedID] = struct{}{}
		out = append(out, Candidate{
			TargetID:       rel.RelatedID,
			Title:          rel.RelatedTitle,
			SourceConcept:  w.ConceptSlug,
			SourceSeverity: severity,
			RelationType:   rel.RelationType,
			AnchorTargetID: &rel.AnchorID,
			AnchorTitle:    rel.AnchorTitle,
			Reason:         fmt.Sprintf("struggling on %s; %s is a %s of %s (never attempted)", w.ConceptSlug, rel.RelatedTitle, rel.RelationType, rel.AnchorTitle),
		})
	}
	return out
}

// acceptVariation encapsulates the five disqualifying checks for a
// variation row. Splitting these out of the candidate loop keeps the
// caller readable and makes each rule independently debuggable.
func (s *Server) acceptVariation(
	ctx context.Context,
	rel *learning.TargetRelation,
	anchorIDs, seenTargets map[uuid.UUID]struct{},
	excludeSet map[string]struct{},
) bool {
	if _, ok := recommendAllowedRelations[rel.RelationType]; !ok {
		return false
	}
	if _, isAnchor := anchorIDs[rel.AnchorID]; !isAnchor {
		return false
	}
	if rel.RelatedAttemptCount > 0 {
		return false
	}
	if _, dup := seenTargets[rel.RelatedID]; dup {
		return false
	}
	// Interleaving filter — skip if the anchor's pattern is in the
	// recent set. The anchor pattern is our proxy for "this kind of
	// problem"; we'd rather push a DIFFERENT pattern's variant next.
	if shouldSkipForInterleaving(ctx, s, rel.AnchorID, excludeSet) {
		return false
	}
	return true
}

// attemptTargetSet flattens an attempt slice into a lookup set of the
// target IDs the user has tried. Used to pick anchors in the variation
// graph — we recommend variants of problems the user has PRACTICED,
// not random targets.
func attemptTargetSet(attempts []learning.Attempt) map[uuid.UUID]struct{} {
	set := make(map[uuid.UUID]struct{}, len(attempts))
	for i := range attempts {
		set[attempts[i].LearningTargetID] = struct{}{}
	}
	return set
}

// dominantSeverity picks the severity label to report alongside a
// candidate. critical > moderate > minor; the first non-zero count wins
// so "critical exists" beats "many minors".
func dominantSeverity(w *learning.WeaknessRow) string {
	switch {
	case w.CriticalCount > 0:
		return "critical"
	case w.ModerateCount > 0:
		return "moderate"
	case w.MinorCount > 0:
		return "minor"
	default:
		return ""
	}
}

// shouldSkipForInterleaving checks whether the anchor target's metadata
// pattern is in the excludeSet. Anchors without metadata.pattern are
// NOT filtered (the set is a positive-match filter, not a deny-unless-
// known filter).
//
// Implementation note: we peek at the most recent attempt on the anchor
// target to find its pattern. This is a soft heuristic — the same target
// may be tagged with different patterns across attempts. Good enough for
// this filter; a stricter version would aggregate patterns across all
// attempts on the target.
func shouldSkipForInterleaving(ctx context.Context, s *Server, anchorID uuid.UUID, excludeSet map[string]struct{}) bool {
	if len(excludeSet) == 0 {
		return false
	}
	attempts, err := s.learn.AttemptsByLearningTarget(ctx, anchorID, 1)
	if err != nil || len(attempts) == 0 {
		return false
	}
	pattern := extractMetadataPattern(attempts[0].Metadata)
	if pattern == "" {
		return false
	}
	_, inExclude := excludeSet[pattern]
	return inExclude
}

// rankCandidates sorts by severity (critical > moderate > minor > other),
// then by relation priority (harder_variant > follow_up > same_pattern >
// similar_structure). Stable sort so the insertion order of weaknesses
// is preserved within ties.
func rankCandidates(candidates []Candidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		si := severityRank[candidates[i].SourceSeverity]
		sj := severityRank[candidates[j].SourceSeverity]
		if candidates[i].SourceSeverity == "" {
			si = len(severityRank)
		}
		if candidates[j].SourceSeverity == "" {
			sj = len(severityRank)
		}
		if si != sj {
			return si < sj
		}
		ri := recommendAllowedRelations[candidates[i].RelationType]
		rj := recommendAllowedRelations[candidates[j].RelationType]
		return ri < rj
	})
}
