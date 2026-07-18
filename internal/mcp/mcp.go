// Copyright 2026 Koopa. All rights reserved.

// Package mcp provides the Model Context Protocol server that exposes
// Koopa's planning and publication workflows to AI agents. Tools are
// organized by workflow rather than
// entity CRUD; the canonical tool catalog lives in internal/mcp/ops.
// Callers self-identify per call; that identity is recorded as attribution
// (created_by / activity actor) and scopes caller-owned reads and writes.
// Access control is the MCP transport, not a tool-layer authorization gate.
package mcp
