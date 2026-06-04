// Copyright 2026 Koopa. All rights reserved.

// Command gen rewrites the generated tool-inventory block in the
// koopa-system skills manual (references/tools.md) from the canonical MCP
// tool catalog. It is invoked by the //go:generate directive in
// internal/mcp/ops/catalog.go, which runs it with the working directory
// set to internal/mcp/ops — hence the relative path up to the repo root.
//
//	go generate ./internal/mcp/ops
package main

import (
	"fmt"
	"os"

	"github.com/Koopa0/koopa/internal/mcp/ops"
)

// manualPath is relative to internal/mcp/ops (the directory go:generate
// runs in), not the repo root.
const manualPath = "../../../skills/koopa-system/references/tools.md"

func main() {
	if err := run(manualPath); err != nil {
		fmt.Fprintln(os.Stderr, "gen tool-inventory:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is the manualPath compile-time const; build-time codegen, no external input
	if err != nil {
		return fmt.Errorf("reading manual: %w", err)
	}
	updated, err := ops.ReplaceToolInventory(string(raw))
	if err != nil {
		return err
	}
	if updated == string(raw) {
		return nil // already in sync
	}
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil { // #nosec G703 -- path is the manualPath compile-time const; build-time codegen, no external input
		return fmt.Errorf("writing manual: %w", err)
	}
	return nil
}
