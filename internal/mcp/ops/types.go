// Package ops holds the static catalog of MCP tool metadata.
//
// This package is intentionally dependency-free: it imports no database,
// no MCP SDK, no handler code. It exists as a single source of truth that
// both the MCP server (which registers handlers) and the admin HTTP layer
// (which serves tool inventory metadata) can import without pulling in
// unrelated surface area.
//
// The catalog declared here is matched against actual server registrations
// by a drift test in the mcp package; adding a tool without a catalog entry
// or a catalog entry without a registration will fail that test.
package ops

// Domain groups tools by the workflow they serve. These labels are for
// humans and UIs; they do not affect dispatch.
type Domain string

const (
	DomainQuery    Domain = "query"    // read-only context, dashboards, search
	DomainDaily    Domain = "daily"    // GTD capture, task lifecycle, daily plan
	DomainA2A      Domain = "a2a"      // tasks, artifacts, acknowledgement
	DomainLearning Domain = "learning" // sessions, attempts, learning plans
	DomainContent  Domain = "content"  // content lifecycle, feeds, bookmarks
	DomainMeta     Domain = "meta"     // proposal/commit, agent notes, hypotheses
	DomainSystem   Domain = "system"   // system health, cross-session bridges
)

// Writability describes the side-effect character of a tool. It maps to
// MCP ToolAnnotations at registration time.
type Writability string

const (
	// ReadOnly tools never modify state.
	ReadOnly Writability = "read_only"
	// Additive tools create new rows but do not mutate existing state.
	Additive Writability = "additive"
	// Idempotent tools may write, but repeating the same call is a no-op.
	Idempotent Writability = "idempotent"
	// Destructive tools transition state in ways that matter (task complete,
	// plan activate, directive resolve).
	Destructive Writability = "destructive"
)

// Stability tracks the contract guarantee a tool offers callers.
type Stability string

const (
	StabilityStable     Stability = "stable"
	StabilityBeta       Stability = "beta"
	StabilityDeprecated Stability = "deprecated"
)

// Meta is the static metadata for one MCP tool. Handler code lives in the
// mcp package; this struct holds only what can be served to clients without
// executing anything.
type Meta struct {
	Name        string      `json:"name"`
	Domain      Domain      `json:"domain"`
	Writability Writability `json:"writability"`
	Stability   Stability   `json:"stability"`
	Since       string      `json:"since"`
	Description string      `json:"description"`
}
