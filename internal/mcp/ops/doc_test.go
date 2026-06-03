// Copyright 2026 Koopa. All rights reserved.

package ops_test

import (
	"os"
	"testing"

	"github.com/Koopa0/koopa/internal/mcp/ops"
)

// manualPath is relative to this package directory (internal/mcp/ops), which
// is the working directory under `go test`.
const manualPath = "../../../skills/koopa-system/references/tools.md"

// TestToolInventoryDocInSync guards the koopa-system skills manual against
// drifting from the canonical catalog. If a tool is added, removed, or
// renamed in catalog.go without rerunning the generator, the committed
// manual's inventory block stops matching ops.RenderToolInventory and this
// test fails. Fix: `go generate ./internal/mcp/ops`.
func TestToolInventoryDocInSync(t *testing.T) {
	raw, err := os.ReadFile(manualPath)
	if err != nil {
		t.Fatalf("reading manual %s: %v", manualPath, err)
	}
	want, err := ops.ReplaceToolInventory(string(raw))
	if err != nil {
		t.Fatalf("rendering inventory: %v", err)
	}
	if string(raw) != want {
		t.Errorf("tool inventory in %s is stale — run `go generate ./internal/mcp/ops`", manualPath)
	}
}
