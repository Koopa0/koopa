package handlers

import (
	"strings"
	"testing"
)

func TestParseArtifact_Complete(t *testing.T) {
	t.Parallel()

	input := `Here's the code:
<artifact type="code" language="go" title="main.go">
package main
func main() {}
</artifact>
That's the implementation.`

	artifact, before, after := parseArtifact(input)

	if artifact == nil {
		t.Fatal("expected artifact to be parsed")
	}
	if artifact.Type != "code" {
		t.Errorf("type = %q, want code", artifact.Type)
	}
	if artifact.Language != "go" {
		t.Errorf("language = %q, want go", artifact.Language)
	}
	if artifact.Title != "main.go" {
		t.Errorf("title = %q, want main.go", artifact.Title)
	}
	if !strings.Contains(artifact.Content, "package main") {
		t.Errorf("content missing expected code")
	}
	if !strings.Contains(before, "Here's the code:") {
		t.Errorf("before missing expected text: %q", before)
	}
	if !strings.Contains(after, "That's the implementation") {
		t.Errorf("after missing expected text: %q", after)
	}
}

func TestParseArtifact_AttributeOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantType  string
		wantLang  string
		wantTitle string
	}{
		{
			name:      "standard order",
			input:     `<artifact type="code" language="go" title="main.go">content</artifact>`,
			wantType:  "code",
			wantLang:  "go",
			wantTitle: "main.go",
		},
		{
			name:      "reversed order",
			input:     `<artifact title="main.go" language="go" type="code">content</artifact>`,
			wantType:  "code",
			wantLang:  "go",
			wantTitle: "main.go",
		},
		{
			name:      "mixed order",
			input:     `<artifact language="python" type="code" title="script.py">content</artifact>`,
			wantType:  "code",
			wantLang:  "python",
			wantTitle: "script.py",
		},
		{
			name:      "markdown type",
			input:     `<artifact type="markdown" language="" title="README.md">content</artifact>`,
			wantType:  "markdown",
			wantLang:  "",
			wantTitle: "README.md",
		},
		{
			name:      "html type",
			input:     `<artifact type="html" language="html" title="index.html">content</artifact>`,
			wantType:  "html",
			wantLang:  "html",
			wantTitle: "index.html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			artifact, _, _ := parseArtifact(tt.input)
			if artifact == nil {
				t.Fatal("expected artifact")
			}
			if artifact.Type != tt.wantType {
				t.Errorf("type = %q, want %q", artifact.Type, tt.wantType)
			}
			if artifact.Language != tt.wantLang {
				t.Errorf("language = %q, want %q", artifact.Language, tt.wantLang)
			}
			if artifact.Title != tt.wantTitle {
				t.Errorf("title = %q, want %q", artifact.Title, tt.wantTitle)
			}
		})
	}
}

func TestParseArtifact_PartialTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantBefore string
		wantAfter  string
	}{
		{
			name:       "partial opening tag",
			input:      "Some text <artifact ty",
			wantBefore: "Some text ",
			wantAfter:  "<artifact ty",
		},
		{
			name:       "complete open, no close",
			input:      `<artifact type="code" language="go" title="x">content`,
			wantBefore: "",
			wantAfter:  `<artifact type="code" language="go" title="x">content`,
		},
		{
			name:       "just less than",
			input:      "Hello <",
			wantBefore: "Hello ",
			wantAfter:  "<",
		},
		{
			name:       "partial artifact word",
			input:      "Text <artif",
			wantBefore: "Text ",
			wantAfter:  "<artif",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			artifact, before, after := parseArtifact(tt.input)
			if artifact != nil {
				t.Error("expected no artifact for partial tag")
			}
			if before != tt.wantBefore {
				t.Errorf("before = %q, want %q", before, tt.wantBefore)
			}
			if after != tt.wantAfter {
				t.Errorf("after = %q, want %q", after, tt.wantAfter)
			}
		})
	}
}

func TestParseArtifact_NoArtifact(t *testing.T) {
	t.Parallel()

	input := "Just regular text without any artifact tags."
	artifact, before, after := parseArtifact(input)

	if artifact != nil {
		t.Error("expected no artifact")
	}
	if before != input {
		t.Errorf("before = %q, want full input", before)
	}
	if after != "" {
		t.Errorf("after = %q, want empty", after)
	}
}

func TestParseArtifact_MultipleArtifacts(t *testing.T) {
	t.Parallel()

	input := `First artifact:
<artifact type="code" language="go" title="a.go">code A</artifact>
Second artifact:
<artifact type="code" language="python" title="b.py">code B</artifact>
Done.`

	// First parse
	art1, before1, remaining := parseArtifact(input)
	if art1 == nil {
		t.Fatal("expected first artifact")
	}
	if art1.Title != "a.go" {
		t.Errorf("first title = %q, want a.go", art1.Title)
	}
	if art1.Language != "go" {
		t.Errorf("first language = %q, want go", art1.Language)
	}
	if !strings.Contains(before1, "First artifact:") {
		t.Errorf("before1 missing expected text")
	}

	// Second parse from remaining
	art2, before2, after2 := parseArtifact(remaining)
	if art2 == nil {
		t.Fatal("expected second artifact")
	}
	if art2.Title != "b.py" {
		t.Errorf("second title = %q, want b.py", art2.Title)
	}
	if art2.Language != "python" {
		t.Errorf("second language = %q, want python", art2.Language)
	}
	if !strings.Contains(before2, "Second artifact:") {
		t.Errorf("before2 missing expected text")
	}
	if !strings.Contains(after2, "Done.") {
		t.Errorf("after2 missing expected text")
	}
}

func TestParseArtifact_EmptyContent(t *testing.T) {
	t.Parallel()

	input := `<artifact type="code" language="go" title="empty.go"></artifact>`
	artifact, _, _ := parseArtifact(input)

	if artifact == nil {
		t.Fatal("expected artifact even with empty content")
	}
	if artifact.Content != "" {
		t.Errorf("content = %q, want empty", artifact.Content)
	}
}

func TestParseArtifact_InvalidType(t *testing.T) {
	t.Parallel()

	input := `<artifact type="unknown" language="go" title="test.go">content</artifact>`
	artifact, _, _ := parseArtifact(input)

	if artifact == nil {
		t.Fatal("expected artifact")
	}
	// Invalid type should default to "code"
	if artifact.Type != "code" {
		t.Errorf("type = %q, want code (default)", artifact.Type)
	}
}

func TestExtractAttr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		tag  string
		name string
		want string
	}{
		{`type="code" language="go" title="main.go"`, "type", "code"},
		{`type="code" language="go" title="main.go"`, "language", "go"},
		{`type="code" language="go" title="main.go"`, "title", "main.go"},
		{`type="code" language="go" title="main.go"`, "missing", ""},
		{`language="" type="code"`, "language", ""},
		{`type="code"`, "type", "code"},
		{`title="file with spaces.go"`, "title", "file with spaces.go"},
	}

	for _, tt := range tests {
		// Create safe test name (truncate tag if too long)
		tagPreview := tt.tag
		if len(tagPreview) > 20 {
			tagPreview = tagPreview[:20]
		}
		t.Run(tt.name+"_in_"+tagPreview, func(t *testing.T) {
			t.Parallel()
			got := extractAttr(tt.tag, tt.name)
			if got != tt.want {
				t.Errorf("extractAttr(%q, %q) = %q, want %q", tt.tag, tt.name, got, tt.want)
			}
		})
	}
}

func TestHasPartialTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{"Hello world", false},
		{"Hello <", true},
		{"Hello <a", true},
		{"Hello <ar", true},
		{"Hello <art", true},
		{"Hello <arti", true},
		{"Hello <artif", true},
		{"Hello <artifa", true},
		{"Hello <artifac", true},
		{"Hello <artifact", true},
		{"Hello <artifact ", true},
		{"Hello <other", false},
		{"<artifact>content</artifact>", false},
		{"text<artifact type", false}, // Complete tag start, not partial
		{"", false},
		{"<", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := hasPartialTag(tt.input)
			if got != tt.want {
				t.Errorf("hasPartialTag(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsValidArtifactType(t *testing.T) {
	t.Parallel()

	valid := []string{"code", "markdown", "html"}
	invalid := []string{"unknown", "script", "", "CODE", "Code", "MARKDOWN"}

	for _, v := range valid {
		if !isValidArtifactType(v) {
			t.Errorf("isValidArtifactType(%q) = false, want true", v)
		}
	}
	for _, v := range invalid {
		if isValidArtifactType(v) {
			t.Errorf("isValidArtifactType(%q) = true, want false", v)
		}
	}
}

func TestSafeSplit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		wantSafe string
		wantHeld string
	}{
		{
			name:     "no partial tag",
			input:    "Hello world",
			wantSafe: "Hello world",
			wantHeld: "",
		},
		{
			name:     "partial at end",
			input:    "Hello <",
			wantSafe: "Hello ",
			wantHeld: "<",
		},
		{
			name:     "partial artifact",
			input:    "Text <artif",
			wantSafe: "Text ",
			wantHeld: "<artif",
		},
		{
			name:     "complete tag",
			input:    "Text <artifact type=",
			wantSafe: "Text <artifact type=",
			wantHeld: "",
		},
		{
			name:     "empty string",
			input:    "",
			wantSafe: "",
			wantHeld: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			safe, held := safeSplit(tt.input)
			if safe != tt.wantSafe {
				t.Errorf("safe = %q, want %q", safe, tt.wantSafe)
			}
			if held != tt.wantHeld {
				t.Errorf("held = %q, want %q", held, tt.wantHeld)
			}
		})
	}
}

func TestParseArtifact_SpecialCharactersInContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantContent string
	}{
		{
			name:    "newlines",
			input:   "<artifact type=\"code\" language=\"go\" title=\"t.go\">line1\nline2\nline3</artifact>",
			wantContent: "line1\nline2\nline3",
		},
		{
			name:    "tabs",
			input:   "<artifact type=\"code\" language=\"go\" title=\"t.go\">\tfunc() {}</artifact>",
			wantContent: "\tfunc() {}",
		},
		{
			name:    "quotes in content",
			input:   `<artifact type="code" language="go" title="t.go">fmt.Println("hello")</artifact>`,
			wantContent: `fmt.Println("hello")`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			artifact, _, _ := parseArtifact(tt.input)
			if artifact == nil {
				t.Fatal("expected artifact")
			}
			if artifact.Content != tt.wantContent {
				t.Errorf("content = %q, want %q", artifact.Content, tt.wantContent)
			}
		})
	}
}
