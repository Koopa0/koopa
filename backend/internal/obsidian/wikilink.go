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

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inCodeBlock = !inCodeBlock
			continue
		}
		if inCodeBlock {
			continue
		}

		// Scan for [[ ]] pairs in this line
		for i := 0; i < len(line)-3; i++ {
			if line[i] != '[' || line[i+1] != '[' {
				continue
			}
			// Found [[, look for ]]
			end := strings.Index(line[i+2:], "]]")
			if end < 0 {
				break // no closing ]] on this line
			}
			inner := line[i+2 : i+2+end]
			if inner == "" {
				i = i + 2 + end + 1
				continue
			}

			var l Link
			if pipe := strings.IndexByte(inner, '|'); pipe >= 0 {
				l.Path = strings.TrimSpace(inner[:pipe])
				l.Display = strings.TrimSpace(inner[pipe+1:])
			} else {
				l.Path = strings.TrimSpace(inner)
			}

			if l.Path != "" {
				if _, ok := seen[l.Path]; !ok {
					seen[l.Path] = struct{}{}
					links = append(links, l)
				}
			}

			i = i + 2 + end + 1 // skip past ]]
		}
	}

	if links == nil {
		return []Link{}
	}
	return links
}
