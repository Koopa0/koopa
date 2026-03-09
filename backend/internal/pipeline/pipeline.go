// Package pipeline handles webhook processing and content sync orchestration.
package pipeline

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// ErrInvalidSignature is returned when the GitHub webhook signature does not match.
var ErrInvalidSignature = errors.New("invalid signature")

// PushEvent represents a GitHub push webhook payload.
type PushEvent struct {
	Ref     string       `json:"ref"`
	Commits []PushCommit `json:"commits"`
}

// PushCommit represents a single commit in a push event.
type PushCommit struct {
	Added    []string `json:"added"`
	Modified []string `json:"modified"`
	Removed  []string `json:"removed"`
}

// ChangedFiles returns deduplicated file paths from all commits that were added or modified.
func (e PushEvent) ChangedFiles() []string {
	seen := make(map[string]bool)
	var files []string

	for _, c := range e.Commits {
		for _, f := range c.Added {
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
		for _, f := range c.Modified {
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
	}

	return files
}

// VerifySignature verifies a GitHub webhook HMAC-SHA256 signature.
// The signature header is expected in the format "sha256=<hex>".
func VerifySignature(payload []byte, signature, secret string) error {
	if !strings.HasPrefix(signature, "sha256=") {
		return ErrInvalidSignature
	}

	sigHex := strings.TrimPrefix(signature, "sha256=")
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return ErrInvalidSignature
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := mac.Sum(nil)

	if !hmac.Equal(sigBytes, expected) {
		return ErrInvalidSignature
	}

	return nil
}
