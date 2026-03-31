package learning

import (
	"strings"
	"testing"
)

func TestValidateLearningMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		learningType string
		metadata     map[string]any
		wantErr      bool
	}{
		{
			name:         "empty learning type accepts anything",
			learningType: "",
			metadata:     map[string]any{"random": "data"},
		},
		{
			name:         "nil metadata with empty type",
			learningType: "",
			metadata:     nil,
		},
		{
			name:         "invalid learning type",
			learningType: "invalid",
			metadata:     map[string]any{},
			wantErr:      true,
		},
		{
			name:         "valid leetcode with no metadata",
			learningType: "leetcode",
			metadata:     map[string]any{},
		},
		{
			name:         "valid leetcode with problem_number",
			learningType: "leetcode",
			metadata:     map[string]any{"problem_number": float64(49)},
		},
		{
			name:         "valid book-reading with key_concepts",
			learningType: "book-reading",
			metadata: map[string]any{
				"book":    "DDIA",
				"chapter": "Chapter 5",
				"key_concepts": []any{
					map[string]any{"name": "Replication", "understanding": "clear"},
					map[string]any{"name": "Consensus", "understanding": "fuzzy"},
				},
			},
		},
		{
			name:         "invalid key_concept understanding",
			learningType: "book-reading",
			metadata: map[string]any{
				"key_concepts": []any{
					map[string]any{"name": "X", "understanding": "bad-value"},
				},
			},
			wantErr: true,
		},
		{
			name:         "key_concept missing name",
			learningType: "course",
			metadata: map[string]any{
				"key_concepts": []any{
					map[string]any{"understanding": "clear"},
				},
			},
			wantErr: true,
		},
		{
			name:         "key_concept missing understanding",
			learningType: "system-design",
			metadata: map[string]any{
				"key_concepts": []any{
					map[string]any{"name": "Load Balancer"},
				},
			},
			wantErr: true,
		},
		{
			name:         "valid weakness observations",
			learningType: "leetcode",
			metadata: map[string]any{
				"weakness_observations": []any{
					map[string]any{
						"tag":         "weakness:constraints-analysis",
						"observation": "did not check constraints",
						"status":      "persistent",
					},
				},
			},
		},
		{
			name:         "weakness observation missing tag",
			learningType: "leetcode",
			metadata: map[string]any{
				"weakness_observations": []any{
					map[string]any{
						"observation": "something",
						"status":      "new",
					},
				},
			},
			wantErr: true,
		},
		{
			name:         "weakness observation invalid status",
			learningType: "leetcode",
			metadata: map[string]any{
				"weakness_observations": []any{
					map[string]any{
						"tag":         "weakness:x",
						"observation": "something",
						"status":      "invalid-status",
					},
				},
			},
			wantErr: true,
		},
		{
			name:         "weakness observations wrong type",
			learningType: "leetcode",
			metadata: map[string]any{
				"weakness_observations": "not-an-array",
			},
			wantErr: true,
		},
		{
			name:         "valid language type",
			learningType: "language",
			metadata: map[string]any{
				"language":         "Japanese",
				"activity_type":    "shadowing",
				"duration_minutes": float64(30),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateLearningMetadata(tt.learningType, tt.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateLearningMetadata(%q, %v) error = %v, wantErr %v",
					tt.learningType, tt.metadata, err, tt.wantErr)
			}
		})
	}
}

func TestExtractObservation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata []byte
		tag      string
		want     string
	}{
		{
			name:     "nil metadata",
			metadata: nil,
			tag:      "weakness:x",
			want:     "",
		},
		{
			name:     "empty metadata",
			metadata: []byte(`{}`),
			tag:      "weakness:x",
			want:     "",
		},
		{
			name:     "no weakness_observations key",
			metadata: []byte(`{"learning_type":"leetcode"}`),
			tag:      "weakness:x",
			want:     "",
		},
		{
			name:     "tag found",
			metadata: []byte(`{"weakness_observations":[{"tag":"weakness:x","observation":"missed it","status":"new"}]}`),
			tag:      "weakness:x",
			want:     "missed it",
		},
		{
			name:     "tag not found",
			metadata: []byte(`{"weakness_observations":[{"tag":"weakness:y","observation":"other","status":"new"}]}`),
			tag:      "weakness:x",
			want:     "",
		},
		{
			name:     "malformed json",
			metadata: []byte(`not json`),
			tag:      "weakness:x",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractObservation(tt.metadata, tt.tag)
			if got != tt.want {
				t.Errorf("extractObservation(%q) = %q, want %q", tt.tag, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateConceptBreakdown — direct tests (unexported, accessible in same pkg)
// ---------------------------------------------------------------------------

func TestValidateConceptBreakdown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   any
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid: all mastery enums present",
			input: []any{
				map[string]any{"concept": "recognize applicability", "mastery": "independent"},
				map[string]any{"concept": "handle rotation", "mastery": "guided", "coaching_hint": "check mid"},
				map[string]any{"concept": "edge search", "mastery": "told"},
				map[string]any{"concept": "two-pass pivot", "mastery": "not_explored"},
				map[string]any{"concept": "hint approach", "mastery": "independent_after_hint"},
			},
		},
		{
			name: "valid: minimal — concept + mastery only",
			input: []any{
				map[string]any{"concept": "binary search", "mastery": "independent"},
			},
		},
		{
			name:    "invalid: not an array",
			input:   map[string]any{"concept": "x", "mastery": "independent"},
			wantErr: true,
		},
		{
			name: "invalid: missing concept",
			input: []any{
				map[string]any{"mastery": "independent"},
			},
			wantErr: true,
			errMsg:  "[0]: concept is required",
		},
		{
			name: "invalid: missing mastery",
			input: []any{
				map[string]any{"concept": "binary search"},
			},
			wantErr: true,
			errMsg:  "[0]: mastery is required",
		},
		{
			name: "invalid: bad mastery enum",
			input: []any{
				map[string]any{"concept": "binary search", "mastery": "expert"},
			},
			wantErr: true,
			errMsg:  "[0]: invalid mastery",
		},
		{
			name: "invalid: second element has bad mastery",
			input: []any{
				map[string]any{"concept": "ok", "mastery": "independent"},
				map[string]any{"concept": "bad", "mastery": "unknown"},
			},
			wantErr: true,
			errMsg:  "[1]: invalid mastery",
		},
		{
			name:  "valid: empty array",
			input: []any{},
		},
		{
			name: "invalid: element is not an object",
			input: []any{
				"not-an-object",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateConceptBreakdown(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateConceptBreakdown() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateConceptBreakdown() error = %q, want it to contain %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateVariationLinks — direct tests
// ---------------------------------------------------------------------------

func TestValidateVariationLinks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   any
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid: all relationship types",
			input: []any{
				map[string]any{"problem_number": float64(81), "relationship": "harder_variant"},
				map[string]any{"problem_number": float64(35), "relationship": "easier_variant"},
				map[string]any{"problem_number": float64(34), "relationship": "prerequisite"},
				map[string]any{"problem_number": float64(240), "relationship": "follow_up"},
				map[string]any{"problem_number": float64(162), "relationship": "same_pattern"},
				map[string]any{"problem_number": float64(278), "relationship": "similar_structure"},
			},
		},
		{
			name:  "valid: empty array",
			input: []any{},
		},
		{
			name: "valid: with optional notes",
			input: []any{
				map[string]any{"problem_number": float64(81), "relationship": "harder_variant", "notes": "with duplicates"},
			},
		},
		{
			name:    "invalid: not an array",
			input:   "not-an-array",
			wantErr: true,
		},
		{
			name: "invalid: missing problem_number (zero value)",
			input: []any{
				map[string]any{"relationship": "harder_variant"},
			},
			wantErr: true,
			errMsg:  "[0]: problem_number is required",
		},
		{
			name: "invalid: problem_number is zero",
			input: []any{
				map[string]any{"problem_number": float64(0), "relationship": "harder_variant"},
			},
			wantErr: true,
			errMsg:  "[0]: problem_number is required",
		},
		{
			name: "invalid: missing relationship",
			input: []any{
				map[string]any{"problem_number": float64(81)},
			},
			wantErr: true,
			errMsg:  "[0]: relationship is required",
		},
		{
			name: "invalid: bad relationship enum",
			input: []any{
				map[string]any{"problem_number": float64(81), "relationship": "copy_of"},
			},
			wantErr: true,
			errMsg:  "[0]: invalid relationship",
		},
		{
			name: "invalid: element not an object",
			input: []any{
				42,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateVariationLinks(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateVariationLinks() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateVariationLinks() error = %q, want it to contain %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateSolveContext — direct tests
// ---------------------------------------------------------------------------

func TestValidateSolveContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   any
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid: solve_context with stuck_points",
			input: map[string]any{
				"result":             "ac-with-hints",
				"time_spent_minutes": float64(45),
				"stuck_points": []any{
					map[string]any{"at": "determining search half", "resolved_by": "coaching_hint"},
					map[string]any{"at": "off-by-one", "resolved_by": "self", "duration": "5m"},
				},
			},
		},
		{
			name: "valid: stuck_points missing (optional)",
			input: map[string]any{
				"result": "ac-independent",
			},
		},
		{
			name:  "valid: empty object",
			input: map[string]any{},
		},
		{
			name: "valid: all resolved_by enums",
			input: map[string]any{
				"stuck_points": []any{
					map[string]any{"at": "a", "resolved_by": "self"},
					map[string]any{"at": "b", "resolved_by": "coaching_hint"},
					map[string]any{"at": "c", "resolved_by": "saw_solution"},
					map[string]any{"at": "d", "resolved_by": "gave_up"},
				},
			},
		},
		{
			name:    "invalid: not an object",
			input:   "ac-with-hints",
			wantErr: true,
		},
		{
			name: "invalid: stuck_points not an array",
			input: map[string]any{
				"stuck_points": "should be array",
			},
			wantErr: true,
			errMsg:  "stuck_points: expected array",
		},
		{
			name: "invalid: stuck_point element not an object",
			input: map[string]any{
				"stuck_points": []any{42},
			},
			wantErr: true,
			errMsg:  "stuck_points[0]:",
		},
		{
			name: "invalid: stuck_point missing at",
			input: map[string]any{
				"stuck_points": []any{
					map[string]any{"resolved_by": "self"},
				},
			},
			wantErr: true,
			errMsg:  "stuck_points[0]: at is required",
		},
		{
			name: "invalid: stuck_point missing resolved_by",
			input: map[string]any{
				"stuck_points": []any{
					map[string]any{"at": "determining search half"},
				},
			},
			wantErr: true,
			errMsg:  "stuck_points[0]: resolved_by is required",
		},
		{
			name: "invalid: bad resolved_by enum",
			input: map[string]any{
				"stuck_points": []any{
					map[string]any{"at": "determining search half", "resolved_by": "magic"},
				},
			},
			wantErr: true,
			errMsg:  "stuck_points[0]: invalid resolved_by",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateSolveContext(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateSolveContext() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateSolveContext() error = %q, want it to contain %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateLearningMetadata — integration: leetcode with new fields
// ---------------------------------------------------------------------------

func TestValidateLearningMetadata_LeetCodeNewFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata map[string]any
		wantErr  bool
	}{
		{
			name: "valid: full leetcode metadata with all new fields",
			metadata: map[string]any{
				"learning_type":  "leetcode",
				"problem_number": float64(33),
				"pattern":        "binary-search",
				"concept_breakdown": []any{
					map[string]any{"concept": "Recognize binary search applicability", "mastery": "independent"},
					map[string]any{"concept": "Rotated array sorted half", "mastery": "guided", "coaching_hint": "hint text"},
				},
				"variation_links": []any{
					map[string]any{"problem_number": float64(81), "relationship": "harder_variant", "notes": "with duplicates"},
				},
				"solve_context": map[string]any{
					"result": "ac-with-hints",
					"stuck_points": []any{
						map[string]any{"at": "determining search half", "resolved_by": "coaching_hint"},
					},
				},
				"alternative_approaches": []any{
					map[string]any{"name": "two-pass pivot search", "explored": false},
				},
			},
		},
		{
			name: "valid: concept_breakdown without coaching_hint",
			metadata: map[string]any{
				"concept_breakdown": []any{
					map[string]any{"concept": "basic binary search", "mastery": "independent"},
				},
			},
		},
		{
			name: "valid: empty variation_links",
			metadata: map[string]any{
				"variation_links": []any{},
			},
		},
		{
			name: "valid: solve_context without stuck_points",
			metadata: map[string]any{
				"solve_context": map[string]any{
					"result": "ac-independent",
				},
			},
		},
		{
			name: "invalid: concept_breakdown bad mastery",
			metadata: map[string]any{
				"concept_breakdown": []any{
					map[string]any{"concept": "x", "mastery": "bad-value"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid: variation_links bad relationship",
			metadata: map[string]any{
				"variation_links": []any{
					map[string]any{"problem_number": float64(81), "relationship": "mirror"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid: solve_context bad resolved_by",
			metadata: map[string]any{
				"solve_context": map[string]any{
					"stuck_points": []any{
						map[string]any{"at": "x", "resolved_by": "unknown"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid: concept_breakdown missing concept field",
			metadata: map[string]any{
				"concept_breakdown": []any{
					map[string]any{"mastery": "guided"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid: variation_links missing problem_number",
			metadata: map[string]any{
				"variation_links": []any{
					map[string]any{"relationship": "harder_variant"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateLearningMetadata("leetcode", tt.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateLearningMetadata(leetcode, ...) error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
