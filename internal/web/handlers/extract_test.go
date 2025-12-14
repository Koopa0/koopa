package handlers

import (
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/stretchr/testify/assert"
)

func TestExtractTextContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		parts []*ai.Part
		want  string
	}{
		{
			name:  "nil parts",
			parts: nil,
			want:  "",
		},
		{
			name:  "empty parts",
			parts: []*ai.Part{},
			want:  "",
		},
		{
			name: "single text part",
			parts: []*ai.Part{
				{Kind: ai.PartText, Text: "Hello"},
			},
			want: "Hello",
		},
		{
			name: "multiple text parts",
			parts: []*ai.Part{
				{Kind: ai.PartText, Text: "Hello "},
				{Kind: ai.PartText, Text: "World"},
			},
			want: "Hello World",
		},
		{
			name: "nil part in slice",
			parts: []*ai.Part{
				{Kind: ai.PartText, Text: "Hello"},
				nil,
				{Kind: ai.PartText, Text: " World"},
			},
			want: "Hello World",
		},
		{
			name: "media part included",
			parts: []*ai.Part{
				{Kind: ai.PartText, Text: "Text "},
				{Kind: ai.PartMedia, Text: "media content"},
			},
			want: "Text media content",
		},
		{
			name: "mixed types with tool call",
			parts: []*ai.Part{
				{Kind: ai.PartText, Text: "Before "},
				{Kind: ai.PartToolRequest, Text: "tool data"},
				{Kind: ai.PartText, Text: "After"},
			},
			want: "Before After",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractTextContent(tt.parts)
			assert.Equal(t, tt.want, got)
		})
	}
}
