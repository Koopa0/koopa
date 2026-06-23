// Copyright 2026 Koopa. All rights reserved.

// Package mcp provides the Model Context Protocol server that exposes
// the koopa knowledge engine to AI agents as workflow-driven tools —
// planning briefs, GTD capture, and knowledge search over the content,
// reading, and song corpus. Tools are organized by workflow rather than
// entity CRUD; the canonical tool catalog lives in internal/mcp/ops.
// Callers self-identify per call and every mutation is authorized
// against the caller's agent identity.
package mcp
