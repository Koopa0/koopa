package security

import (
	"regexp"
	"strings"
	"unicode"
)

// PromptInjectionResult contains details about detected injection attempts.
type PromptInjectionResult struct {
	Safe     bool     // True if no injection patterns detected
	Patterns []string // List of detected patterns (empty if safe)
}

// PromptValidator detects potential prompt injection attempts.
// This provides a first line of defense against common injection patterns.
//
// Note: No filter is perfect. This catches common patterns but sophisticated
// attacks may bypass detection. Defense in depth (system prompt hardening,
// output filtering) is recommended.
//
// Known limitation: Homoglyph attacks are NOT detected. Attackers can use
// visually similar Unicode characters (e.g., Greek 'Ι' U+0399 for Latin 'I',
// Cyrillic 'а' U+0430 for Latin 'a') to bypass pattern matching. Full homoglyph
// normalization requires Unicode confusables mapping which adds complexity.
// See: https://unicode.org/reports/tr39/#Confusable_Detection
type PromptValidator struct {
	patterns []*regexp.Regexp
}

// NewPromptValidator creates a PromptValidator with default patterns.
func NewPromptValidator() *PromptValidator {
	patterns := []string{
		// System prompt override attempts
		`(?i)ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)`,
		`(?i)disregard\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?)`,
		`(?i)forget\s+(all\s+)?(previous|above|prior)\s+(instructions?|context)`,
		`(?i)override\s+(all\s+)?(previous|above|prior)\s+(instructions?|rules?)`,

		// Role-playing attacks
		`(?i)^(pretend|act|behave|imagine)\s+(you\s+are|to\s+be|as\s+if|like)`,
		`(?i)^you\s+are\s+now\s+a`,
		`(?i)^from\s+now\s+on,?\s+you\s+(are|will|must)`,

		// Instruction injection
		`(?i)^\s*(important|critical|urgent|system)\s*:\s*`,
		`(?i)^new\s+(instruction|task|rule)\s*:`,
		`(?i)^admin\s*(mode|override|command)\s*:`,

		// Delimiter manipulation (trying to escape context)
		`(?i)\]\s*\[\s*(system|assistant|instruction)`,
		`(?i)</?(system|instruction|prompt)>`,
		`(?i)---+\s*(system|new\s+instruction)`,

		// Jailbreak attempts
		`(?i)do\s+anything\s+now`,
		`(?i)jailbreak`,
		`(?i)bypass\s+(safety|filter|restrictions?)`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}

	return &PromptValidator{patterns: compiled}
}

// Validate checks input for prompt injection patterns.
// Returns a result indicating whether the input is safe.
func (v *PromptValidator) Validate(input string) PromptInjectionResult {
	// Normalize: remove excessive whitespace, normalize unicode
	normalized := normalizeInput(input)

	var detected []string

	for _, re := range v.patterns {
		if re.MatchString(normalized) {
			detected = append(detected, re.String())
		}
	}

	return PromptInjectionResult{
		Safe:     len(detected) == 0,
		Patterns: detected,
	}
}

// IsSafe is a convenience method that returns true if no patterns detected.
func (v *PromptValidator) IsSafe(input string) bool {
	return v.Validate(input).Safe
}

// normalizeInput prepares input for pattern matching.
// - Converts to lowercase for case-insensitive matching
// - Normalizes whitespace
// - Removes zero-width characters that could evade detection
func normalizeInput(s string) string {
	// Remove zero-width and invisible characters
	var b strings.Builder
	for _, r := range s {
		// Skip zero-width and format characters
		if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Mn, r) {
			continue
		}
		// Normalize different types of spaces/whitespace
		if unicode.IsSpace(r) {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}

	// Collapse multiple spaces
	result := strings.Join(strings.Fields(b.String()), " ")
	return result
}
