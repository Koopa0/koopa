package obsidian

import "strings"

// Link represents a parsed wikilink from Obsidian markdown content.
type Link struct {
	Path    string // target note path (before | if present)
	Display string // display text (after | if present, empty otherwise)
}

// ParseWikilinks extracts all [[...]] wikilinks from markdown content.
// Handles [[path]], [[path|display text]], and ignores links inside fenced code blocks.
// Returns deduplicated links by path.
func ParseWikilinks(content string) []Link {
	var links []Link
	seen := map[string]struct{}{}
	inCodeBlock := false

	lines := strings.SplitSeq(content, "\n")
	for line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inCodeBlock = !inCodeBlock
			continue
		}
		if inCodeBlock {
			continue
		}

		links = extractLineWikilinks(line, seen, links)
	}

	if links == nil {
		return []Link{}
	}
	return links
}

// extractLineWikilinks scans a single line for [[ ]] pairs and appends deduplicated links.
func extractLineWikilinks(line string, seen map[string]struct{}, links []Link) []Link {
	for i := 0; i < len(line)-3; i++ {
		if line[i] != '[' || line[i+1] != '[' {
			continue
		}
		end := strings.Index(line[i+2:], "]]")
		if end < 0 {
			break
		}
		inner := line[i+2 : i+2+end]
		if inner == "" {
			i = i + 2 + end + 1
			continue
		}

		l := parseWikilinkInner(inner)
		if l.Path != "" {
			if _, ok := seen[l.Path]; !ok {
				seen[l.Path] = struct{}{}
				links = append(links, l)
			}
		}

		i = i + 2 + end + 1
	}
	return links
}

// parseWikilinkInner parses the content between [[ and ]] into a Link.
func parseWikilinkInner(inner string) Link {
	if before, after, ok := strings.Cut(inner, "|"); ok {
		return Link{Path: strings.TrimSpace(before), Display: strings.TrimSpace(after)}
	}
	return Link{Path: strings.TrimSpace(inner)}
}
