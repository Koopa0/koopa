// Package api provides the JSON REST API server for Koopa.
//
// # Architecture
//
// The API server uses Go 1.22+ routing with a layered middleware stack:
//
//	Recovery → RequestID → Logging → CORS → RateLimit → User → Session → CSRF → Routes
//
// Health probes (/health, /ready) bypass the middleware stack via a
// top-level mux, ensuring they remain fast and unauthenticated.
//
// # Endpoints
//
// Health probes (no middleware):
//   - GET /health — returns {"status":"ok"}
//   - GET /ready  — returns {"status":"ok"}
//
// CSRF provisioning:
//   - GET /api/v1/csrf-token — returns pre-session or session-bound token
//
// Session CRUD (ownership-enforced):
//   - POST   /api/v1/sessions              — create new session
//   - GET    /api/v1/sessions              — list caller's sessions
//   - GET    /api/v1/sessions/{id}         — get session by ID
//   - GET    /api/v1/sessions/{id}/messages — get session messages
//   - DELETE /api/v1/sessions/{id}         — delete session
//   - GET    /api/v1/sessions/{id}/export  — export session
//
// Chat (ownership-enforced):
//   - POST /api/v1/chat        — initiate chat, returns stream URL
//   - GET  /api/v1/chat/stream — SSE endpoint for streaming responses
//
// Search:
//   - GET /api/v1/search — full-text search across messages
//
// Stats:
//   - GET /api/v1/stats — usage statistics (sessions, messages, memories)
//
// Memory (ownership-enforced):
//   - GET    /api/v1/memories        — list memories
//   - POST   /api/v1/memories        — create memory
//   - DELETE /api/v1/memories/{id}   — delete memory
//   - GET    /api/v1/memories/search — search memories
//
// # CSRF Token Model
//
// Two token types prevent cross-site request forgery:
//
//   - Pre-session tokens ("pre:nonce:timestamp:signature"): issued before
//     a session exists, valid for the first POST /sessions call.
//
//   - Session-bound tokens ("timestamp:signature"): bound to a specific
//     session via HMAC-SHA256, verified with constant-time comparison.
//
// Both expire after 1 hour with 5 minutes of clock skew tolerance.
//
// # Session Ownership
//
// All session-accessing endpoints verify that the requested resource
// matches the caller's session cookie. This prevents session enumeration
// and cross-session data access.
//
// # Error Handling
//
// All responses use an envelope format:
//
//	Success: {"data": <payload>}
//	Error:   {"error": {"code": "...", "message": "..."}}
//
// Tool errors during chat are sent as SSE events (event: error),
// not HTTP error responses, since SSE headers are already committed.
//
// # SSE Streaming
//
// Chat responses stream via Server-Sent Events with typed events:
//
//   - chunk:         incremental text content
//   - tool_start:    tool execution began
//   - tool_complete: tool execution succeeded
//   - tool_error:    tool execution failed
//   - done:          final response with session metadata
//   - error:         flow-level error
//
// # Security
//
// The middleware stack enforces:
//   - CSRF protection for state-changing requests
//   - Per-IP rate limiting (token bucket, 60 req/min burst)
//   - CORS with explicit origin allowlist
//   - Security headers (CSP, HSTS, X-Frame-Options, etc.)
//   - HttpOnly, Secure, SameSite=Lax session cookies
package api
