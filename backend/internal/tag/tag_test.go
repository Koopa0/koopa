package tag

import "testing"

func TestSlugify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "lowercase passthrough", input: "golang", want: "golang"},
		{name: "uppercase to lower", input: "GoLang", want: "golang"},
		{name: "spaces to hyphens", input: "my tag", want: "my-tag"},
		{name: "underscores to hyphens", input: "my_tag", want: "my-tag"},
		{name: "slashes to hyphens", input: "path/to/tag", want: "path-to-tag"},
		{name: "dots to hyphens", input: "io.Reader", want: "io-reader"},
		{name: "consecutive special chars collapse", input: "a--b__c  d", want: "a-b-c-d"},
		{name: "trim leading special", input: " -tag", want: "tag"},
		{name: "trim trailing special", input: "tag- ", want: "tag"},
		{name: "digits preserved", input: "go1.22", want: "go1-22"},
		{name: "empty string", input: "", want: ""},
		{name: "only special chars", input: "---", want: ""},
		{name: "unicode letters", input: "日本語", want: "日本語"},
		{name: "mixed unicode and ascii", input: "Go 語言", want: "go-語言"},
		{name: "real tag: binary-search", input: "binary-search", want: "binary-search"},
		{name: "real tag: Dynamic Programming", input: "Dynamic Programming", want: "dynamic-programming"},
		{name: "real tag: C++", input: "C++", want: "c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Slugify(tt.input)
			if got != tt.want {
				t.Errorf("Slugify(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// FuzzSlugify verifies Slugify never panics on arbitrary input and always
// produces valid slug characters (lowercase letters, digits, hyphens, unicode letters).
// Scene: user-supplied tags from Obsidian YAML can contain any UTF-8 string.
func FuzzSlugify(f *testing.F) {
	f.Add("golang")
	f.Add("Dynamic Programming")
	f.Add("C++")
	f.Add("日本語")
	f.Add("")
	f.Add("---")
	f.Add("a  b\tc\nd")

	f.Fuzz(func(t *testing.T, input string) {
		result := Slugify(input)
		// Must not end with hyphen
		if result != "" && result[len(result)-1] == '-' {
			t.Errorf("Slugify(%q) = %q ends with hyphen", input, result)
		}
		// Must not start with hyphen
		if result != "" && result[0] == '-' {
			t.Errorf("Slugify(%q) = %q starts with hyphen", input, result)
		}
		// Must not contain consecutive hyphens
		for i := 1; i < len(result); i++ {
			if result[i] == '-' && result[i-1] == '-' {
				t.Errorf("Slugify(%q) = %q has consecutive hyphens", input, result)
				break
			}
		}
	})
}

// BenchmarkSlugify measures slug generation for a realistic tag.
// Scene: ResolveTags processes N tags per content sync — slug perf matters at scale.
func BenchmarkSlugify(b *testing.B) {
	for b.Loop() {
		Slugify("Dynamic Programming Algorithms")
	}
}
