package component

import (
	"net/url"
	"strings"

	"github.com/koopa0/koopa-cli/internal/security"
)

// orDefault returns val if non-empty, otherwise returns def.
func orDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}

// isValidAvatarURL validates that a URL is safe for <img src> usage.
// Uses existing security.URL validator for SSRF protection.
//
// Allows:
//   - Empty URLs (fallback to initials)
//   - Relative URLs (/api/avatar/123)
//   - External HTTPS URLs (https://example.com/avatar.jpg)
//
// Blocks:
//   - javascript:, data:, file: schemes (XSS)
//   - localhost, private IPs (SSRF)
//   - Extremely long URLs (>2048 chars, DoS)
func isValidAvatarURL(rawURL string) bool {
	if rawURL == "" {
		return true // Allow empty (fallback to initials)
	}

	// DoS protection - limit URL length
	if len(rawURL) > 2048 {
		return false
	}

	// Allow relative URLs (same-origin, no SSRF risk)
	if strings.HasPrefix(rawURL, "/") {
		// Decode URL-encoded sequences before validation
		// This prevents bypasses like %2e%2e (URL-encoded ..)
		decoded, err := url.PathUnescape(rawURL)
		if err != nil {
			return false // Malformed URL encoding
		}

		// Check for path traversal by examining each path component
		// This correctly handles:
		// - "/images/../../../etc/passwd" → blocked (.. as component)
		// - "/images/my..image.jpg" → allowed (.. in filename, not component)
		// - "/%2e%2e/etc/passwd" → blocked (decoded .. as component)
		parts := strings.Split(decoded, "/")
		for _, part := range parts {
			// Block ".." as a path component (path traversal)
			if part == ".." {
				return false
			}
		}

		return true
	}

	// Block dangerous schemes explicitly (XSS vectors)
	lowerURL := strings.ToLower(rawURL)
	dangerousSchemes := []string{"javascript:", "data:", "file:", "ftp:", "gopher:"}
	for _, scheme := range dangerousSchemes {
		if strings.HasPrefix(lowerURL, scheme) {
			return false
		}
	}

	// For absolute URLs, use existing security validator
	urlValidator := security.NewURL()
	if err := urlValidator.Validate(rawURL); err != nil {
		return false
	}

	return true
}

// getInitials extracts up to 2 initials from a name.
// Example: "John Doe" -> "JD", "Alice" -> "A", "" -> "?"
//
// Handles edge cases safely:
//   - Empty name returns "?"
//   - Whitespace-only returns "?"
//   - Unicode names handled correctly
func getInitials(name string) string {
	if name == "" {
		return "?"
	}

	parts := strings.Fields(name) // Removes empty strings from whitespace
	if len(parts) == 0 {
		return "?"
	}

	// firstRune safely extracts the first UTF-8 rune.
	// Uses range (idiomatic, zero-allocation, handles invalid UTF-8).
	firstRune := func(s string) string {
		for _, r := range s {
			return string(r)
		}
		return ""
	}

	// Get first initial with bounds check
	firstInitial := firstRune(parts[0])
	if firstInitial == "" {
		return "?"
	}

	if len(parts) == 1 {
		return strings.ToUpper(firstInitial)
	}

	// Get last initial with bounds check
	lastInitial := firstRune(parts[len(parts)-1])
	if lastInitial == "" {
		return strings.ToUpper(firstInitial) // Fallback to first only
	}

	return strings.ToUpper(firstInitial + lastInitial)
}

// ButtonType represents valid HTML button type attributes.
// Using Go enums provides compile-time safety.
type ButtonType string

const (
	ButtonTypeButton ButtonType = "button"
	ButtonTypeSubmit ButtonType = "submit"
	ButtonTypeReset  ButtonType = "reset"
)

// String returns the string representation for templ.
// Invalid values return safe default to prevent arbitrary string injection.
func (t ButtonType) String() string {
	switch t {
	case ButtonTypeButton, ButtonTypeSubmit, ButtonTypeReset:
		return string(t)
	case "":
		return string(ButtonTypeButton) // Default to "button"
	default:
		// Invalid enum value - return safe default
		// This prevents arbitrary string injection in HTML attributes
		return string(ButtonTypeButton)
	}
}

// BadgeVariant represents badge color variants.
type BadgeVariant string

const (
	BadgeVariantDefault BadgeVariant = "default"
	BadgeVariantSuccess BadgeVariant = "success"
	BadgeVariantError   BadgeVariant = "error"
	BadgeVariantWarning BadgeVariant = "warning"
)

// String returns the string representation.
// Invalid values return safe default to prevent arbitrary string injection.
func (v BadgeVariant) String() string {
	switch v {
	case BadgeVariantDefault, BadgeVariantSuccess, BadgeVariantError, BadgeVariantWarning:
		return string(v)
	case "":
		return string(BadgeVariantDefault)
	default:
		// Invalid enum value - return safe default
		return string(BadgeVariantDefault)
	}
}

// BadgeSize represents badge size variants.
type BadgeSize string

const (
	BadgeSizeSmall  BadgeSize = "sm"
	BadgeSizeMedium BadgeSize = "md"
)

// String returns the string representation.
// Invalid values return safe default to prevent arbitrary string injection.
func (s BadgeSize) String() string {
	switch s {
	case BadgeSizeSmall, BadgeSizeMedium:
		return string(s)
	case "":
		return string(BadgeSizeSmall)
	default:
		// Invalid enum value - return safe default
		return string(BadgeSizeSmall)
	}
}
