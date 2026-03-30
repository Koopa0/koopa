package learning

import (
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
