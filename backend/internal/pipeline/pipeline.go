// Package pipeline handles webhook processing and content sync orchestration.
package pipeline

import (
	"github.com/koopa0/blog-backend/internal/webhook"
)

// ErrInvalidSignature is an alias for webhook.ErrInvalidSignature for backward compatibility.
var ErrInvalidSignature = webhook.ErrInvalidSignature

// VerifySignature delegates to webhook.VerifySignature.
func VerifySignature(payload []byte, signature, secret string) error {
	return webhook.VerifySignature(payload, signature, secret)
}

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
