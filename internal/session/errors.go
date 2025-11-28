package session

import "errors"

// Branch name constants and constraints.
// These MUST match internal/config package constants to maintain consistency.
const (
	// DefaultBranch is the default branch name for conversation history.
	DefaultBranch = "main"

	// MaxBranchLength is the maximum length for a branch name.
	// Matches config.MaxBranchLength for consistency.
	MaxBranchLength = 256

	// MaxBranchDepth is the maximum number of dot-separated segments.
	// Matches config.MaxBranchDepth for consistency.
	MaxBranchDepth = 10

	// DefaultHistoryLimit is the default number of messages to load per branch.
	// Matches config.DefaultMaxHistoryMessages for consistency.
	DefaultHistoryLimit int32 = 100

	// MaxHistoryLimit is the absolute maximum to prevent OOM.
	// Matches config.MaxAllowedHistoryMessages for consistency.
	MaxHistoryLimit int32 = 10000

	// MinHistoryLimit is the minimum allowed value for history limit.
	// Matches config.MinHistoryMessages for consistency.
	MinHistoryLimit int32 = 10
)

// Sentinel errors for session operations.
// These errors are part of the Store's public API and should be checked using errors.Is().
//
// Example:
//
//	sess, err := store.GetSession(ctx, id)
//	if errors.Is(err, session.ErrSessionNotFound) {
//	    // Handle missing session
//	}
var (
	// ErrSessionNotFound indicates the requested session does not exist in the database.
	ErrSessionNotFound = errors.New("session not found")

	// ErrInvalidBranch indicates the branch name format is invalid.
	ErrInvalidBranch = errors.New("invalid branch name")

	// ErrBranchTooLong indicates the branch name exceeds MaxBranchLength.
	ErrBranchTooLong = errors.New("branch name too long")

	// ErrBranchTooDeep indicates the branch has too many dot-separated segments.
	ErrBranchTooDeep = errors.New("branch too deep")
)

// NormalizeBranch validates and normalizes a branch name.
// Empty branch defaults to DefaultBranch ("main").
//
// Branch format rules (matches config.ValidateBranch):
//   - Branch format: "segment" or "segment1.segment2.segment3"
//   - Each segment must start with a letter and contain only alphanumeric chars and underscores
//   - Maximum total length is MaxBranchLength (256)
//   - Maximum depth is MaxBranchDepth (10 segments)
//
// Examples of valid branches: "main", "main.research", "chat.agent1.subtask"
// Examples of invalid branches: ".main", "main.", "main..sub", "123abc"
func NormalizeBranch(branch string) (string, error) {
	if branch == "" {
		return DefaultBranch, nil
	}

	if len(branch) > MaxBranchLength {
		return "", ErrBranchTooLong
	}

	segments := splitBranch(branch)
	if len(segments) > MaxBranchDepth {
		return "", ErrBranchTooDeep
	}

	for _, seg := range segments {
		if seg == "" {
			return "", ErrInvalidBranch // Empty segment (consecutive dots or leading/trailing dot)
		}
		if !isValidSegment(seg) {
			return "", ErrInvalidBranch
		}
	}

	return branch, nil
}

// splitBranch splits a branch name by dots.
func splitBranch(branch string) []string {
	if branch == "" {
		return nil
	}

	var segments []string
	start := 0
	for i := range branch {
		if branch[i] == '.' {
			segments = append(segments, branch[start:i])
			start = i + 1
		}
	}
	segments = append(segments, branch[start:])
	return segments
}

// isValidSegment checks if a branch segment is valid.
// A valid segment starts with a letter and contains only alphanumeric characters and underscores.
func isValidSegment(seg string) bool {
	if len(seg) == 0 {
		return false
	}

	// First character must be a letter
	first := seg[0]
	if (first < 'a' || first > 'z') && (first < 'A' || first > 'Z') {
		return false
	}

	// Remaining characters must be alphanumeric or underscore
	for i := 1; i < len(seg); i++ {
		c := seg[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}

	return true
}

// NormalizeHistoryLimit normalizes the history limit value.
// Returns DefaultHistoryLimit for zero/negative values.
// Clamps to MinHistoryLimit/MaxHistoryLimit as bounds.
func NormalizeHistoryLimit(limit int32) int32 {
	if limit <= 0 {
		return DefaultHistoryLimit
	}
	if limit < MinHistoryLimit {
		return MinHistoryLimit
	}
	if limit > MaxHistoryLimit {
		return MaxHistoryLimit
	}
	return limit
}
