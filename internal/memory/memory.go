// Package memory provides persistent user memory backed by pgvector.
//
// Memories are facts extracted from conversations via LLM, deduplicated
// by cosine similarity on embeddings, and injected into chat prompts.
// All logic runs in-process — no external services required.
package memory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/koopa0/koopa/internal/rag"
)

// Sentinel errors for memory operations.
var (
	ErrNotFound  = errors.New("memory not found")
	ErrForbidden = errors.New("forbidden")
)

// Category classifies a memory fact.
type Category string

const (
	// CategoryIdentity represents persistent user traits (name, location, role).
	CategoryIdentity Category = "identity"
	// CategoryContextual represents situational facts (recent decisions, temporary state).
	CategoryContextual Category = "contextual"
	// CategoryPreference represents opinions and choices (tools, frameworks, coding style).
	CategoryPreference Category = "preference"
	// CategoryProject represents current work context (project name, tech stack, deadlines).
	CategoryProject Category = "project"
)

// Valid reports whether c is a known category.
func (c Category) Valid() bool {
	switch c {
	case CategoryIdentity, CategoryContextual, CategoryPreference, CategoryProject:
		return true
	}
	return false
}

// DefaultTTL returns the default time-to-live for memories in this category.
// Returns 0 for categories that never expire (identity).
func (c Category) DefaultTTL() time.Duration {
	switch c {
	case CategoryIdentity:
		return 0 // never expires
	case CategoryPreference:
		return 90 * 24 * time.Hour
	case CategoryProject:
		return 60 * 24 * time.Hour
	case CategoryContextual:
		return 30 * 24 * time.Hour
	}
	return 30 * 24 * time.Hour // unreachable if Valid() is checked first
}

// AllCategories returns all valid categories in priority order (identity first).
func AllCategories() []Category {
	return []Category{
		CategoryIdentity,
		CategoryPreference,
		CategoryProject,
		CategoryContextual,
	}
}

// ExpiresAt calculates the expiration timestamp from category TTL.
// Returns nil for categories that never expire (identity).
func (c Category) ExpiresAt() *time.Time {
	ttl := c.DefaultTTL()
	if ttl == 0 {
		return nil
	}
	t := time.Now().Add(ttl)
	return &t
}

// DecayLambda returns the exponential decay rate (per hour) for this category.
// Lambda = ln(2) / half-life, where half-life = TTL/2.
// Returns 0 for categories that never expire.
func (c Category) DecayLambda() float64 {
	ttl := c.DefaultTTL()
	if ttl == 0 {
		return 0
	}
	halfLife := ttl.Hours() / 2
	return math.Log(2) / halfLife
}

// VectorDimension matches the embedding column size.
// Canonical source: rag.VectorDimension. Aliased here to avoid changing
// 20+ references in memory package tests.
const VectorDimension = rag.VectorDimension

// Two-threshold dedup constants.
const (
	// AutoMergeThreshold: similarity >= this auto-merges (UPDATE in-place).
	AutoMergeThreshold = 0.95
	// ArbitrationThreshold: similarity in [0.85, 0.95) triggers LLM arbitration.
	ArbitrationThreshold = 0.85
)

// ArbitrationTimeout is the context timeout for LLM arbitration calls.
const ArbitrationTimeout = 30 * time.Second

// MaxContentLength is the maximum length for a single memory fact in bytes.
const MaxContentLength = 500

// MaxPerUser is the hard cap on active memories per user.
// Prevents unbounded growth; HNSW handles search efficiently at this scale.
const MaxPerUser = 1000

// EmbedTimeout is the context timeout for embedding API calls.
// 15s accommodates remote providers (Gemini, OpenAI) with network latency.
const EmbedTimeout = 15 * time.Second

// DecayInterval is how often the scheduler recalculates decay scores.
const DecayInterval = 1 * time.Hour

// Hybrid search weights (must sum to 1.0).
const (
	searchWeightVector = 0.6
	searchWeightText   = 0.2
	searchWeightDecay  = 0.2
)

// MaxSearchQueryLen caps query length for HybridSearch to prevent abuse.
const MaxSearchQueryLen = 1000

// maxTopK caps the number of results from Search/HybridSearch to prevent
// excessive memory allocation and database load from unbounded topK values.
const maxTopK = 100

// Memory represents a single extracted fact about a user.
type Memory struct {
	ID              uuid.UUID
	OwnerID         string
	Content         string
	Category        Category
	SourceSessionID uuid.UUID // zero value if source session was deleted
	Active          bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Importance      int        // 1-10 scale
	AccessCount     int        // times returned in search results
	LastAccessedAt  *time.Time // nil if never accessed
	DecayScore      float64    // 0.0-1.0, recalculated periodically
	SupersededBy    *uuid.UUID // nil if not superseded
	ExpiresAt       *time.Time // nil = never expires
	Score           float64    // populated by HybridSearch only
}

// ExtractedFact is a fact extracted from a conversation by the LLM.
type ExtractedFact struct {
	Content    string   `json:"content"`
	Category   Category `json:"category"`
	Importance int      `json:"importance,omitempty"`
	ExpiresIn  string   `json:"expires_in,omitempty"` // "7d", "30d", "90d", "" (never)
}

// Operation is the LLM-decided action for a memory conflict.
type Operation string

const (
	OpAdd    Operation = "ADD"
	OpUpdate Operation = "UPDATE"
	OpDelete Operation = "DELETE"
	OpNoop   Operation = "NOOP"
)

// ArbitrationResult is the LLM's decision for a memory conflict.
type ArbitrationResult struct {
	Operation Operation `json:"operation"`
	Content   string    `json:"content,omitempty"`   // merged content (for UPDATE)
	Reasoning string    `json:"reasoning,omitempty"` // explanation (for logging)
}

// Arbitrator resolves conflicts between existing and candidate memories.
// Defined here for Store.Add() parameter; implemented in chat package.
type Arbitrator interface {
	Arbitrate(ctx context.Context, existing, candidate string) (*ArbitrationResult, error)
}

// AddOpts carries optional parameters for Add().
// Zero value gives safe defaults: importance=5, no expiry override.
type AddOpts struct {
	Importance int    // 1-10, default 5 if 0
	ExpiresIn  string // "7d", "30d", "90d", or "" for category default
}

// maxExpiresIn caps custom expiry at 365 days.
const maxExpiresIn = 365 * 24 * time.Hour

// expiresInRe matches duration strings like "7d", "30d", "24h", "60m".
var expiresInRe = regexp.MustCompile(`^(\d+)([dhm])$`)

// parseExpiresIn converts a duration string like "7d", "30d", "90d" to time.Duration.
// Returns 0 for empty string (use category default). Returns error for invalid format.
// Caps at 365 days.
func parseExpiresIn(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	m := expiresInRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid expires_in format: %q", s)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("parsing expires_in number: %w", err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("expires_in must be positive: %q", s)
	}
	var d time.Duration
	switch m[2] {
	case "d":
		d = time.Duration(n) * 24 * time.Hour
	case "h":
		d = time.Duration(n) * time.Hour
	case "m":
		d = time.Duration(n) * time.Minute
	}
	if d > maxExpiresIn {
		d = maxExpiresIn
	}
	return d, nil
}
