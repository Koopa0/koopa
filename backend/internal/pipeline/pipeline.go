// Package pipeline handles webhook processing and content sync orchestration.
package pipeline

// PushEvent represents a GitHub push webhook payload.
type PushEvent struct {
	Ref        string         `json:"ref"`
	Repository PushRepository `json:"repository"`
	Commits    []PushCommit   `json:"commits"`
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

// RemovedFiles returns deduplicated file paths from all commits that were removed.
func (e PushEvent) RemovedFiles() []string {
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
