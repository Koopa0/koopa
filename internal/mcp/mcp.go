// Copyright 2026 Koopa. All rights reserved.

// Package mcp provides the Model Context Protocol server that exposes
// the koopa knowledge engine to AI agents as workflow-driven tools —
// planning briefs, GTD capture, knowledge search, the learning-session
// lifecycle, and Zettelkasten note co-authoring. Tools are organized by
// workflow rather than entity CRUD; the canonical tool catalog lives in
// internal/mcp/ops. Callers self-identify per call and every mutation
// is authorized against the caller's agent identity.
package mcp
