// Copyright 2026 Koopa. All rights reserved.

// doc.go renders the generated tool-inventory block for the koopa-system
// skills manual (references/tools.md) from the canonical catalog (All()).
// The block keeps the manual's tool list and counts in lockstep with the
// registered tools: a drift test (doc_test.go) fails when the committed
// manual is stale, and `go generate ./internal/mcp/ops` (the directive in
// catalog.go) rewrites it. Only the inventory between the markers is
// generated — the manual's hand-written usage prose and per-tool param
// tables live outside the markers and are never touched.

package ops

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Markers delimiting the generated region in references/tools.md. The
// generator replaces everything between them; the surrounding manual is
// preserved verbatim.
const (
	ToolInventoryStart = "<!-- GENERATED:TOOL-INVENTORY START — run: go generate ./internal/mcp/ops -->"
	ToolInventoryEnd   = "<!-- GENERATED:TOOL-INVENTORY END -->"
)

// domainOrder fixes the inventory's domain ordering and supplies a stable
// rank so the flat table sorts deterministically. Any Domain not listed
// here sorts last (and would surface as an obviously-misplaced row, which
// is the intended nudge to add it).
var domainOrder = []Domain{
	DomainQuery,
	DomainDaily,
	DomainA2A,
	DomainMeta,
	DomainLearning,
	DomainContent,
	DomainSystem,
}

func domainRank(d Domain) int {
	for i, dd := range domainOrder {
		if dd == d {
			return i
		}
	}
	return len(domainOrder)
}

// RenderToolInventory builds the generated inventory body (the content that
// sits between the markers, with no surrounding newlines) from All(): a
// per-domain count table followed by one flat table of every tool. It is
// deterministic — same catalog in, same bytes out — which is what lets the
// drift test compare it byte-for-byte against the committed manual.
func RenderToolInventory() string {
	tools := All()

	counts := map[Domain]int{}
	for _, m := range tools {
		counts[m.Domain]++
	}

	rows := make([]Meta, len(tools))
	copy(rows, tools)
	slices.SortStableFunc(rows, func(a, b Meta) int {
		if ri, rj := domainRank(a.Domain), domainRank(b.Domain); ri != rj {
			return cmp.Compare(ri, rj)
		}
		return cmp.Compare(a.Name, b.Name)
	})

	var b strings.Builder
	b.WriteString("> Generated from `internal/mcp/ops/catalog.go::All()` — do NOT edit by hand.\n")
	b.WriteString("> Run `go generate ./internal/mcp/ops` after any change to the tool surface;\n")
	b.WriteString("> the drift test `TestToolInventoryDocInSync` fails CI if this is stale.\n\n")
	fmt.Fprintf(&b, "**%d tools** across %d domains.\n\n", len(tools), len(domainOrder))

	b.WriteString("| Domain | Count |\n|---|---|\n")
	for _, d := range domainOrder {
		fmt.Fprintf(&b, "| `%s` | %d |\n", d, counts[d])
	}
	fmt.Fprintf(&b, "| **Total** | **%d** |\n\n", len(tools))

	b.WriteString("| Tool | Domain | Writability | Purpose |\n|---|---|---|---|\n")
	for i := range rows {
		m := &rows[i]
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", m.Name, m.Domain, m.Writability, firstSentence(m.Description))
	}

	return strings.TrimRight(b.String(), "\n")
}

// ReplaceToolInventory swaps the content between the inventory markers in
// doc with a freshly rendered block, preserving the markers and everything
// around them. It is idempotent: applying it to its own output is a no-op,
// which is the property the drift test relies on. Returns an error if the
// markers are absent or out of order.
func ReplaceToolInventory(doc string) (string, error) {
	s := strings.Index(doc, ToolInventoryStart)
	e := strings.Index(doc, ToolInventoryEnd)
	if s < 0 || e < 0 || e < s {
		return "", fmt.Errorf("ops: tool-inventory markers missing or out of order in manual")
	}
	head := doc[:s+len(ToolInventoryStart)]
	tail := doc[e:]
	return head + "\n\n" + RenderToolInventory() + "\n" + tail, nil
}

// firstSentence reduces a tool description to a single-line purpose: it
// collapses newlines, cuts at the first sentence boundary, caps the length
// on a rune boundary, and escapes the pipe so it cannot break the markdown
// table.
func firstSentence(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")

	cut := len(s)
	for _, sep := range []string{". ", "。", " — ", "; "} {
		if i := strings.Index(s, sep); i > 0 && i < cut {
			cut = i
		}
	}
	s = s[:cut]

	const maxRunes = 150
	if r := []rune(s); len(r) > maxRunes {
		s = strings.TrimSpace(string(r[:maxRunes])) + "…"
	}
	s = strings.TrimSpace(s)
	return strings.ReplaceAll(s, "|", "\\|")
}
