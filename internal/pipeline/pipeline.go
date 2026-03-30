// Package pipeline handles webhook processing and content sync orchestration.
//
// Design note: pipeline is an orchestration layer that coordinates content sync
// (GitHub → DB), webhook routing, and manual trigger endpoints. High import count
// (15 packages) is inherent — sync requires content, note, tag, obsidian, github.
// Internally split into ContentSync, WebhookRouter, and Triggers sub-structs with
// a thin Handler facade. Sub-packaging was evaluated and rejected: the sub-structs
// share the Handler's goroutine pool and backpressure, and splitting would require
// exporting internal coordination types.
package pipeline

// PushEvent represents a GitHub push webhook payload.
type PushEvent struct {
	Before     string         `json:"before"` // SHA before push (all zeros for new branch)
	After      string         `json:"after"`  // head SHA after push
	Ref        string         `json:"ref"`
	Repository PushRepository `json:"repository"`
	Sender     PushSender     `json:"sender"`
	Commits    []PushCommit   `json:"commits"`
}

// PushSender identifies the user who triggered the push.
type PushSender struct {
	Login string `json:"login"`
}

// PushRepository identifies the repository in a push event.
type PushRepository struct {
	FullName string `json:"full_name"` // "owner/repo"
}

// PushCommit represents a single commit in a push event.
type PushCommit struct {
	Message  string   `json:"message"`
	Added    []string `json:"added"`
	Modified []string `json:"modified"`
	Removed  []string `json:"removed"`
}

// ChangedFiles returns deduplicated file paths from all commits that were added or modified.
func (e *PushEvent) ChangedFiles() []string {
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

// PullRequestEvent represents a GitHub pull_request webhook payload.
type PullRequestEvent struct {
	Action      string          `json:"action"`
	PullRequest PullRequestData `json:"pull_request"`
	Repository  PushRepository  `json:"repository"`
	Sender      PushSender      `json:"sender"`
}

// PullRequestData holds the pull request details from a webhook payload.
type PullRequestData struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	Merged bool   `json:"merged"`
}

// RemovedFiles returns deduplicated file paths from all commits that were removed.
func (e *PushEvent) RemovedFiles() []string {
	seen := make(map[string]bool)
	var files []string

	for _, c := range e.Commits {
		for _, f := range c.Removed {
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
	}

	return files
}
