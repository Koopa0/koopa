package obsidian

import "testing"

func TestSplitCamelCase(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// CamelCase basics
		{name: "simple camel", input: "CamelCase", want: "camel case"},
		{name: "lowercase", input: "hello", want: "hello"},
		{name: "all upper", input: "HTTP", want: "http"},

		// Consecutive uppercase
		{name: "HTTPS redirect", input: "HTTPSRedirect", want: "https redirect"},
		{name: "OAuth2 client", input: "OAuth2Client", want: "oauth2 client"},
		{name: "Err redis timeout", input: "ErrRedisConnectionTimeout", want: "err redis connection timeout"},

		// Digits follow previous token
		{name: "OAuth2", input: "OAuth2", want: "oauth2"},

		// Dot separation
		{name: "io.Reader", input: "io.Reader", want: "io reader"},
		{name: "pgxpool.Pool", input: "pgxpool.Pool", want: "pgxpool pool"},
		{name: "genkit.Generate", input: "genkit.Generate", want: "genkit generate"},

		// Underscore separation
		{name: "DDIA_Ch8", input: "DDIA_Ch8", want: "ddia ch8"},
		{name: "snake_case", input: "my_function_name", want: "my function name"},

		// Go bracket syntax
		{name: "slice type", input: "[]string", want: "string"},
		{name: "map type", input: "map[string]interface{}", want: "map string interface"},

		// Wikilinks preserved
		{name: "wikilink simple", input: "[[some-note]]", want: "[[some-note]]"},
		{name: "wikilink in text", input: "see [[some-note]] for details", want: "see [[some-note]] for details"},
		{name: "wikilink with camel", input: "HTTPClient and [[my-note]]", want: "http client and [[my-note]]"},

		// Mixed
		{name: "empty", input: "", want: ""},
		{name: "single char", input: "A", want: "a"},
		{name: "spaces preserved", input: "hello world", want: "hello world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitCamelCase(tt.input)
			if got != tt.want {
				t.Errorf("SplitCamelCase(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
