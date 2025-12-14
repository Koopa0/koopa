// Package handlers provides HTTP handlers for web UI.
package handlers

import "strings"

// Artifact represents a detected code/document artifact from AI output.
// Per rob-pike v4: Single type, no duplication with chat.Artifact.
// Per architecture-master: Handler-layer type for text-parsed artifacts.
type Artifact struct {
	Type     string // "code", "markdown", "html"
	Language string // "go", "python", "javascript", etc.
	Title    string // Filename or description
	Content  string // The artifact content
}

const (
	tagStart      = "<artifact "
	tagEnd        = "</artifact>"
	maxBufferSize = 1 << 20 // 1MB limit per golang-master
)

// parseArtifact extracts a single artifact from text.
// Returns the artifact (if complete), text before it, and remaining text.
// Per rob-pike v4: Simple function, no types, no state machine.
func parseArtifact(text string) (art *Artifact, before, after string) {
	startIdx := strings.Index(text, tagStart)
	if startIdx == -1 {
		// No complete tag start found - check for partial tag at end
		safe, held := safeSplit(text)
		return nil, safe, held
	}

	// Find end of opening tag
	tagBodyStart := startIdx + len(tagStart)
	closeIdx := strings.Index(text[tagBodyStart:], ">")
	if closeIdx == -1 {
		// Partial tag - return text before, hold the rest
		return nil, text[:startIdx], text[startIdx:]
	}
	closeIdx += tagBodyStart

	// Parse attributes (any order - per ai-agent-master)
	tagBody := text[tagBodyStart:closeIdx]
	art = &Artifact{
		Type:     extractAttr(tagBody, "type"),
		Language: extractAttr(tagBody, "language"),
		Title:    extractAttr(tagBody, "title"),
	}

	// Validate type (per ai-agent-master)
	if !isValidArtifactType(art.Type) {
		art.Type = "code" // Safe default
	}

	// Find closing tag
	contentStart := closeIdx + 1
	endIdx := strings.Index(text[contentStart:], tagEnd)
	if endIdx == -1 {
		// No closing tag yet - return text before, hold from tag start
		return nil, text[:startIdx], text[startIdx:]
	}
	endIdx += contentStart

	art.Content = text[contentStart:endIdx]
	return art, text[:startIdx], text[endIdx+len(tagEnd):]
}

// extractAttr extracts an attribute value from a tag body.
// Handles attributes in any order: type="code" language="go" title="main.go"
// Per rob-pike v4: strings.Index is simpler than regex.
func extractAttr(tag, name string) string {
	prefix := name + `="`
	i := strings.Index(tag, prefix)
	if i == -1 {
		return ""
	}
	start := i + len(prefix)
	end := strings.Index(tag[start:], `"`)
	if end == -1 {
		return ""
	}
	return tag[start : start+end]
}

// isValidArtifactType checks if the artifact type is in the allowed set.
// Per ai-agent-master v4: Validate types to prevent unexpected behavior.
func isValidArtifactType(t string) bool {
	switch t {
	case "code", "markdown", "html":
		return true
	default:
		return false
	}
}

// hasPartialTag checks if text ends with a potential partial <artifact tag.
// Per golang-master v4: Fixed logic from v3 (was inverted).
func hasPartialTag(text string) bool {
	// Look for '<' that could start "<artifact "
	for i := len(text) - 1; i >= 0 && i >= len(text)-len(tagStart); i-- {
		if text[i] == '<' {
			remaining := text[i:]
			// Check if "<artifact " starts with this remaining text
			if strings.HasPrefix(tagStart, remaining) {
				return true
			}
		}
	}
	return false
}

// safeSplit splits text, holding back any potential partial tag.
// Returns safe text to emit and held text to keep in buffer.
func safeSplit(text string) (safe, held string) {
	if !hasPartialTag(text) {
		return text, ""
	}
	// Find the '<' that starts the partial tag
	for i := len(text) - 1; i >= 0; i-- {
		if text[i] == '<' {
			return text[:i], text[i:]
		}
	}
	return text, ""
}
