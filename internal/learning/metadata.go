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
