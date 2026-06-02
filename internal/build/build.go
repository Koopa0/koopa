// Copyright 2026 Koopa. All rights reserved.

// Package build exposes the running binary's build identity (commit SHA,
// build time, version). Values are injected via -ldflags at link time —
// see Dockerfile / Dockerfile.mcp. Defaults keep `go build ./...` useful
// locally; "dev" / "unknown" / "v0.0.0-dev" advertise that ldflags didn't
// fire so a deployer notices missing injection.
package build

var (
	SHA     = "dev"
	BuiltAt = "unknown"
	Version = "v0.0.0-dev"
)

// Info is the JSON-serializable shape returned to MCP / health callers.
type Info struct {
	SHA     string `json:"sha"`
	BuiltAt string `json:"built_at"`
	Version string `json:"version"`
}

// Current returns a snapshot of the link-time identity.
func Current() Info {
	return Info{SHA: SHA, BuiltAt: BuiltAt, Version: Version}
}
