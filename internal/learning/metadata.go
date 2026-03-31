package learning

import (
	"fmt"
	"strings"
)

// LearningType constants for per-type metadata discrimination.
const (
	TypeLeetCode     = "leetcode"
	TypeBookReading  = "book-reading"
	TypeCourse       = "course"
	TypeSystemDesign = "system-design"
	TypeLanguage     = "language"
)

var validLearningTypes = map[string]bool{
	TypeLeetCode:     true,
	TypeBookReading:  true,
	TypeCourse:       true,
	TypeSystemDesign: true,
	TypeLanguage:     true,
}

// ValidateLearningMetadata checks metadata structure against the learning_type schema.
// Empty learningType means no structured metadata — any content is accepted.
// Validation is lenient: only checks that known keys have correct types.
// Unknown keys are ignored (forward-compatible).
func ValidateLearningMetadata(learningType string, metadata map[string]any) error {
	if learningType == "" {
		return nil
	}
	if !validLearningTypes[learningType] {
		return fmt.Errorf("invalid learning_type %q (valid: %s)",
			learningType, strings.Join(sortedLearningTypes(), ", "))
	}

	// Validate weakness_observations if present (cross-type).
	if obs, ok := metadata["weakness_observations"]; ok {
		if err := validateWeaknessObservations(obs); err != nil {
			return fmt.Errorf("weakness_observations: %w", err)
		}
	}

	// Validate key_concepts if present (shared by book-reading, course, system-design).
	if kc, ok := metadata["key_concepts"]; ok {
		if err := validateKeyConcepts(kc); err != nil {
			return fmt.Errorf("key_concepts: %w", err)
		}
	}

	// Validate LeetCode-specific structured metadata fields.
	if cb, ok := metadata["concept_breakdown"]; ok {
		if err := validateConceptBreakdown(cb); err != nil {
			return fmt.Errorf("concept_breakdown: %w", err)
		}
	}
	if vl, ok := metadata["variation_links"]; ok {
		if err := validateVariationLinks(vl); err != nil {
			return fmt.Errorf("variation_links: %w", err)
		}
	}
	if sc, ok := metadata["solve_context"]; ok {
		if err := validateSolveContext(sc); err != nil {
			return fmt.Errorf("solve_context: %w", err)
		}
	}

	return nil
}

// WeaknessObservation is the structured format for a single weakness observation
// stored in ai_metadata.weakness_observations.
type WeaknessObservation struct {
	Tag         string `json:"tag"`         // canonical tag with weakness: prefix
	Observation string `json:"observation"` // description of the observed weakness
	Status      string `json:"status"`      // new, persistent, improving, graduated
}

var validObservationStatuses = map[string]bool{
	"new": true, "persistent": true, "improving": true, "graduated": true,
}

func validateWeaknessObservations(v any) error {
	arr, ok := v.([]any)
	if !ok {
		return fmt.Errorf("expected array, got %T", v)
	}
	for i, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("[%d]: expected object, got %T", i, item)
		}
		tag, _ := obj["tag"].(string)
		if tag == "" {
			return fmt.Errorf("[%d]: tag is required", i)
		}
		observation, _ := obj["observation"].(string)
		if observation == "" {
			return fmt.Errorf("[%d]: observation is required", i)
		}
		status, _ := obj["status"].(string)
		if status == "" {
			return fmt.Errorf("[%d]: status is required", i)
		}
		if !validObservationStatuses[status] {
			return fmt.Errorf("[%d]: invalid status %q (valid: new, persistent, improving, graduated)", i, status)
		}
	}
	return nil
}

// ConceptMastery enum values for concept_breakdown[].mastery.
var validConceptMasteries = map[string]bool{
	"independent":            true,
	"independent_after_hint": true,
	"guided":                 true,
	"told":                   true,
	"not_explored":           true,
}

// VariationRelationship enum values for variation_links[].relationship.
var validVariationRelationships = map[string]bool{
	"easier_variant":    true,
	"harder_variant":    true,
	"prerequisite":      true,
	"follow_up":         true,
	"same_pattern":      true,
	"similar_structure": true,
}

// StuckPointResolution enum values for solve_context.stuck_points[].resolved_by.
var validResolutions = map[string]bool{
	"self": true, "coaching_hint": true, "saw_solution": true, "gave_up": true,
}

// ConceptBreakdownEntry is a single concept mastery record from ai_metadata.concept_breakdown.
type ConceptBreakdownEntry struct {
	Concept      string `json:"concept"`
	Mastery      string `json:"mastery"`
	Notes        string `json:"notes,omitempty"`
	CoachingHint string `json:"coaching_hint,omitempty"`
}

// VariationLink is a problem relationship record from ai_metadata.variation_links.
type VariationLink struct {
	ProblemNumber int    `json:"problem_number"`
	Relationship  string `json:"relationship"`
	Notes         string `json:"notes,omitempty"`
}

// SolveContext is the overall result context from ai_metadata.solve_context.
type SolveContext struct {
	Result           string       `json:"result,omitempty"`
	TimeSpentMinutes float64      `json:"time_spent_minutes,omitempty"`
	StuckPoints      []StuckPoint `json:"stuck_points,omitempty"`
}

// StuckPoint records where Koopa got stuck during a problem.
type StuckPoint struct {
	At         string `json:"at"`
	Duration   string `json:"duration,omitempty"`
	ResolvedBy string `json:"resolved_by"`
}

// AlternativeApproach is an alternative solution approach from ai_metadata.alternative_approaches.
type AlternativeApproach struct {
	Name     string `json:"name"`
	Explored bool   `json:"explored"`
	Notes    string `json:"notes,omitempty"`
}

func validateConceptBreakdown(v any) error {
	arr, ok := v.([]any)
	if !ok {
		return fmt.Errorf("expected array, got %T", v)
	}
	for i, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("[%d]: expected object, got %T", i, item)
		}
		concept, _ := obj["concept"].(string)
		if concept == "" {
			return fmt.Errorf("[%d]: concept is required", i)
		}
		mastery, _ := obj["mastery"].(string)
		if mastery == "" {
			return fmt.Errorf("[%d]: mastery is required", i)
		}
		if !validConceptMasteries[mastery] {
			return fmt.Errorf("[%d]: invalid mastery %q (valid: independent, independent_after_hint, guided, told, not_explored)", i, mastery)
		}
	}
	return nil
}

func validateVariationLinks(v any) error {
	arr, ok := v.([]any)
	if !ok {
		return fmt.Errorf("expected array, got %T", v)
	}
	for i, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("[%d]: expected object, got %T", i, item)
		}
		// problem_number can be float64 from JSON unmarshal.
		pn, _ := obj["problem_number"].(float64)
		if pn == 0 {
			return fmt.Errorf("[%d]: problem_number is required", i)
		}
		rel, _ := obj["relationship"].(string)
		if rel == "" {
			return fmt.Errorf("[%d]: relationship is required", i)
		}
		if !validVariationRelationships[rel] {
			return fmt.Errorf("[%d]: invalid relationship %q (valid: easier_variant, harder_variant, prerequisite, follow_up, same_pattern, similar_structure)", i, rel)
		}
	}
	return nil
}

func validateSolveContext(v any) error {
	obj, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("expected object, got %T", v)
	}
	sp, ok := obj["stuck_points"]
	if !ok {
		return nil // stuck_points is optional
	}
	arr, ok := sp.([]any)
	if !ok {
		return fmt.Errorf("stuck_points: expected array, got %T", sp)
	}
	for i, item := range arr {
		spObj, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("stuck_points[%d]: expected object, got %T", i, item)
		}
		at, _ := spObj["at"].(string)
		if at == "" {
			return fmt.Errorf("stuck_points[%d]: at is required", i)
		}
		resolvedBy, _ := spObj["resolved_by"].(string)
		if resolvedBy == "" {
			return fmt.Errorf("stuck_points[%d]: resolved_by is required", i)
		}
		if !validResolutions[resolvedBy] {
			return fmt.Errorf("stuck_points[%d]: invalid resolved_by %q (valid: self, coaching_hint, saw_solution, gave_up)", i, resolvedBy)
		}
	}
	return nil
}

var validUnderstandings = map[string]bool{
	"clear": true, "fuzzy": true, "not-understood": true,
}

func validateKeyConcepts(v any) error {
	arr, ok := v.([]any)
	if !ok {
		return fmt.Errorf("expected array, got %T", v)
	}
	for i, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("[%d]: expected object, got %T", i, item)
		}
		name, _ := obj["name"].(string)
		if name == "" {
			return fmt.Errorf("[%d]: name is required", i)
		}
		understanding, _ := obj["understanding"].(string)
		if understanding == "" {
			return fmt.Errorf("[%d]: understanding is required", i)
		}
		if !validUnderstandings[understanding] {
			return fmt.Errorf("[%d]: invalid understanding %q (valid: clear, fuzzy, not-understood)", i, understanding)
		}
	}
	return nil
}

func sortedLearningTypes() []string {
	return []string{TypeBookReading, TypeCourse, TypeLanguage, TypeLeetCode, TypeSystemDesign}
}
