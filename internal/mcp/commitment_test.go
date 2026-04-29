package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestExtractTitleFromFirstTextPart locks in the strict contract for
// directive title derivation: first request_part must be a text part
// with non-empty text after trim. Anything else is rejected before a
// proposal token is signed.
func TestExtractTitleFromFirstTextPart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		parts     []json.RawMessage
		wantTitle string
		wantErr   string
	}{
		{
			name:      "first text part used as title",
			parts:     []json.RawMessage{[]byte(`{"text":"Investigate HNSW tuning"}`), []byte(`{"data":{"k":1}}`)},
			wantTitle: "Investigate HNSW tuning",
		},
		{
			name:      "text part with surrounding whitespace",
			parts:     []json.RawMessage{[]byte(`{"text":"  Trim me  "}`)},
			wantTitle: "Trim me",
		},
		{
			name:    "empty request_parts rejected",
			parts:   []json.RawMessage{},
			wantErr: "request_parts is empty",
		},
		{
			name:    "first part is data not text rejected",
			parts:   []json.RawMessage{[]byte(`{"data":{"foo":"bar"}}`)},
			wantErr: "must be a text part",
		},
		{
			name:    "first part empty text rejected",
			parts:   []json.RawMessage{[]byte(`{"text":""}`)},
			wantErr: "is empty after trim",
		},
		{
			name:    "first part whitespace text rejected",
			parts:   []json.RawMessage{[]byte(`{"text":"   "}`)},
			wantErr: "is empty after trim",
		},
		{
			name:    "first part text not a string rejected",
			parts:   []json.RawMessage{[]byte(`{"text":123}`)},
			wantErr: "must be a string",
		},
		{
			name:    "first part malformed JSON rejected",
			parts:   []json.RawMessage{[]byte(`not json`)},
			wantErr: "not a valid JSON object",
		},
		{
			name:      "long title rune-truncated to 200 with ellipsis",
			parts:     []json.RawMessage{[]byte(`{"text":"` + strings.Repeat("a", 250) + `"}`)},
			wantTitle: strings.Repeat("a", 200) + "…",
		},
		{
			name:      "exactly 200 runes left intact",
			parts:     []json.RawMessage{[]byte(`{"text":"` + strings.Repeat("b", 200) + `"}`)},
			wantTitle: strings.Repeat("b", 200),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := extractTitleFromFirstTextPart(tt.parts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("extractTitleFromFirstTextPart(...) err = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("extractTitleFromFirstTextPart(...) unexpected err = %v", err)
			}
			if got != tt.wantTitle {
				t.Errorf("extractTitleFromFirstTextPart(...) = %q, want %q", got, tt.wantTitle)
			}
		})
	}
}
