// Package artifact provides Canvas artifact management for Koopa.
//
// An artifact represents interactive content displayed in the Canvas panel
// (code snippets, markdown documents, HTML previews). Each artifact is
// identified by (SessionID, Filename) and belongs to exactly one session.
//
// Design follows Google ADK-go's artifact package pattern where artifacts
// are managed separately from sessions, enabling Canvas as an optional
// feature that can be enabled per-session.
//
// Thread Safety: Store implementations must be safe for concurrent access.
//
// Lifecycle: Artifacts are deleted when their parent session is deleted
// (CASCADE DELETE at database level).
package artifact
