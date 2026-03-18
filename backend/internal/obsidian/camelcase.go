package obsidian

import (
	"strings"
	"unicode"
)

// SplitCamelCase converts CamelCase, snake_case, and dot-separated identifiers
// into space-separated lowercase tokens for full-text search indexing.
//
// Rules:
//   - Consecutive uppercase = one token: "HTTP" → "http"
//   - Digits follow previous token: "OAuth2" → "oauth2"
//   - Dot separates: "io.Reader" → "io reader"
//   - Underscore separates: "DDIA_Ch8" → "ddia ch8"
//   - Wikilinks [[...]] are preserved as-is (not split)
//   - Go bracket syntax is stripped: "[]string" → "string", "map[string]interface{}" → "map string interface"
func SplitCamelCase(s string) string {
	// Preserve wikilinks by extracting and replacing with placeholders.
	var links []string
	result := replaceWikilinks(s, func(link string) string {
		links = append(links, link)
		return "\x00LINK\x00"
	})

	var tokens []string
	for _, part := range splitSeparators(result) {
		if part == "\x00LINK\x00" {
			if len(links) > 0 {
				tokens = append(tokens, links[0])
				links = links[1:]
			}
			continue
		}
		tokens = append(tokens, splitCamelWord(part)...)
	}

	// Join tokens, then normalize whitespace (collapse multiple spaces).
	out := strings.Join(tokens, " ")
	return strings.Join(strings.Fields(out), " ")
}

// replaceWikilinks calls fn for each [[...]] match and replaces it in s.
func replaceWikilinks(s string, fn func(string) string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		if i+1 < len(s) && s[i] == '[' && s[i+1] == '[' {
			end := strings.Index(s[i+2:], "]]")
			if end >= 0 {
				link := s[i : i+2+end+2] // [[...]]
				b.WriteString(fn(link))
				i += 2 + end + 1 // skip past ]]
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// splitSeparators splits on dots, underscores, and bracket syntax.
func splitSeparators(s string) []string {
	var tokens []string
	var current strings.Builder

	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '.', '_':
			flush()
		case '[', ']', '{', '}', '(', ')':
			flush()
		case '\x00':
			flush()
			// Placeholder marker — find end.
			end := strings.IndexByte(s[i+1:], '\x00')
			if end >= 0 {
				tokens = append(tokens, s[i:i+1+end+1])
				i += end + 1
			}
		default:
			current.WriteByte(c)
		}
	}
	flush()
	return tokens
}

// splitCamelWord splits a single word on CamelCase boundaries.
// "HTTPSRedirect" → ["https", "redirect"]
// "OAuth2Client" → ["oauth2", "client"]
func splitCamelWord(word string) []string {
	if word == "" {
		return nil
	}

	runes := []rune(word)
	var tokens []string
	start := 0

	for i := 1; i < len(runes); i++ {
		prev := runes[i-1]
		curr := runes[i]

		split := false
		switch {
		// lowercase/digit → uppercase: "oAuth2C" split before C
		case (unicode.IsLower(prev) || unicode.IsDigit(prev)) && unicode.IsUpper(curr):
			split = true
		// uppercase → uppercase → lowercase: "HTTPSRedirect" split before "R"
		// But only if we have at least 2 chars in current token.
		case unicode.IsUpper(prev) && unicode.IsUpper(curr):
			if i+1 < len(runes) && unicode.IsLower(runes[i+1]) && i-start > 1 {
				split = true
			}
		}

		if split {
			token := strings.ToLower(string(runes[start:i]))
			if token != "" {
				tokens = append(tokens, token)
			}
			start = i
		}
	}

	// Remaining.
	token := strings.ToLower(string(runes[start:]))
	if token != "" {
		tokens = append(tokens, token)
	}

	return tokens
}
