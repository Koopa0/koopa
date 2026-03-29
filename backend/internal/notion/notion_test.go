package notion

import (
	"encoding/json"
	"testing"
)

func TestValidRole(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "projects", input: "projects", want: true},
		{name: "tasks", input: "tasks", want: true},
		{name: "books", input: "books", want: true},
		{name: "goals", input: "goals", want: true},
		{name: "empty", input: "", want: true},
		{name: "invalid", input: "unknown", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidRole(tt.input)
			if got != tt.want {
				t.Errorf("ValidRole(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTitleProperty(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "single text",
			raw:  `{"title":[{"plain_text":"Hello World"}]}`,
			want: "Hello World",
		},
		{
			name: "multiple parts",
			raw:  `{"title":[{"plain_text":"Hello "},{"plain_text":"World"}]}`,
			want: "Hello World",
		},
		{
			name: "empty",
			raw:  `{"title":[]}`,
			want: "",
		},
		{
			name: "invalid json",
			raw:  `{invalid}`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TitleProperty(json.RawMessage(tt.raw))
			if got != tt.want {
				t.Errorf("TitleProperty() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRichTextProperty(t *testing.T) {
	raw := `{"rich_text":[{"plain_text":"Some description"}]}`
	got := RichTextProperty(json.RawMessage(raw))
	if got != "Some description" {
		t.Errorf("RichTextProperty() = %q, want %q", got, "Some description")
	}
}

func TestStatusProperty(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "doing",
			raw:  `{"status":{"name":"Doing"}}`,
			want: "Doing",
		},
		{
			name: "null status",
			raw:  `{"status":null}`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StatusProperty(json.RawMessage(tt.raw))
			if got != tt.want {
				t.Errorf("StatusProperty() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSelectProperty(t *testing.T) {
	raw := `{"select":{"name":"⭐️⭐️⭐️⭐️"}}`
	got := SelectProperty(json.RawMessage(raw))
	if got != "⭐️⭐️⭐️⭐️" {
		t.Errorf("SelectProperty() = %q, want %q", got, "⭐️⭐️⭐️⭐️")
	}
}

func TestDateProperty(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantNil bool
	}{
		{
			name:    "date only",
			raw:     `{"date":{"start":"2026-06-15"}}`,
			wantNil: false,
		},
		{
			name:    "datetime",
			raw:     `{"date":{"start":"2026-06-15T10:00:00Z"}}`,
			wantNil: false,
		},
		{
			name:    "null date",
			raw:     `{"date":null}`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DateProperty(json.RawMessage(tt.raw))
			if tt.wantNil && got != nil {
				t.Errorf("DateProperty() = %v, want nil", got)
			}
			if !tt.wantNil && got == nil {
				t.Error("DateProperty() = nil, want non-nil")
			}
		})
	}
}

func TestCheckboxProperty(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "true", raw: `{"checkbox":true}`, want: true},
		{name: "false", raw: `{"checkbox":false}`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckboxProperty(json.RawMessage(tt.raw))
			if got != tt.want {
				t.Errorf("CheckboxProperty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRelationProperty(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "has relation",
			raw:  `{"relation":[{"id":"abc-123"}]}`,
			want: "abc-123",
		},
		{
			name: "empty relation",
			raw:  `{"relation":[]}`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RelationProperty(json.RawMessage(tt.raw))
			if got != tt.want {
				t.Errorf("RelationProperty() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "simple english", input: "My Project", want: "my-project"},
		{name: "chinese", input: "個人部落格", want: "個人部落格"},
		{name: "mixed", input: "Go 記憶體管理", want: "go-記憶體管理"},
		{name: "special chars", input: "Hello, World!", want: "hello-world"},
		{name: "leading spaces", input: "  trimmed  ", want: "trimmed"},
		{name: "multiple dashes", input: "one---two", want: "one-two"},
		{name: "trailing dash", input: "test-", want: "test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Slugify(tt.input)
			if got != tt.want {
				t.Errorf("Slugify(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
