// Package github provides a client for the GitHub REST API (Contents, Compare, Commits).
package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseSize is the upper bound for GitHub API response bodies (10 MB).
// The Contents API returns base64-encoded files (~1.3x raw size), and the Compare/Commits
// APIs return JSON proportional to diff size. 10 MB covers large responses while
// preventing a malicious or buggy upstream from exhausting memory.
const maxResponseSize = 10 << 20

// ErrNotFound indicates a 404 from the GitHub API (permanent -- file deleted or missing).
var ErrNotFound = errors.New("github: not found")

// Commit represents a single GitHub commit.
type Commit struct {
	SHA     string
	Message string
	Date    time.Time
}

// Client fetches file content from a GitHub repository using the GitHub API.
type Client struct {
	token  string
	repo   string // "owner/repo"
	client *http.Client
}

// NewClient returns a Client with a 15-second HTTP timeout.
func NewClient(token, repo string) *Client {
	return &Client{
		token: token,
		repo:  repo,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// fileResponse represents the GitHub Contents API response.
type fileResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// FileContent fetches the raw content of a file from the repository's default branch.
func (g *Client) FileContent(ctx context.Context, path string) ([]byte, error) {
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", g.repo, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching file: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // drain for keep-alive
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("github %s: %w", path, ErrNotFound)
		}
		return nil, fmt.Errorf("github api returned %d for %s", resp.StatusCode, path)
	}

	var fileResp fileResponse
	if decodeErr := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&fileResp); decodeErr != nil {
		return nil, fmt.Errorf("decoding response: %w", decodeErr)
	}

	if fileResp.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected encoding %q for %s", fileResp.Encoding, path)
	}

	// GitHub API returns base64 with embedded newlines; strip before decoding.
	cleaned := strings.ReplaceAll(fileResp.Content, "\n", "")
	content, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	return content, nil
}

// dirEntry represents a single entry from the GitHub Contents API directory listing.
type dirEntry struct {
	Name string `json:"name"`
	Type string `json:"type"` // "file" or "dir"
}

// ListDirectory lists file names in a directory using the GitHub Contents API.
func (g *Client) ListDirectory(ctx context.Context, path string) ([]string, error) {
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", g.repo, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing directory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // drain for keep-alive
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("github directory %s: %w", path, ErrNotFound)
		}
		return nil, fmt.Errorf("github api returned %d for directory %s", resp.StatusCode, path)
	}

	var entries []dirEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decoding directory listing: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.Type == "file" && strings.HasSuffix(e.Name, ".md") {
			names = append(names, strings.TrimSuffix(e.Name, ".md"))
		}
	}
	return names, nil
}

// compareResponse represents the relevant fields from the GitHub Compare API.
type compareResponse struct {
	TotalCommits int           `json:"total_commits"`
	Files        []compareFile `json:"files"`
}

// compareFile represents a single file in a compare response.
type compareFile struct {
	Additions int `json:"additions"`
	Deletions int `json:"deletions"`
}

// DiffStats holds diff statistics from a GitHub compare response.
type DiffStats struct {
	LinesAdded   int `json:"lines_added"`
	LinesRemoved int `json:"lines_removed"`
	FilesChanged int `json:"files_changed"`
	CommitCount  int `json:"commit_count"`
}

// Compare fetches diff stats between two commits using the GitHub Compare API.
// repo is "owner/repo", base and head are commit SHAs.
func (g *Client) Compare(ctx context.Context, repo, base, head string) (*DiffStats, error) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid repo format %q: expected owner/repo", repo)
	}
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/compare/%s...%s",
		url.PathEscape(parts[0]), url.PathEscape(parts[1]),
		url.PathEscape(base), url.PathEscape(head))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating compare request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching compare: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // drain for keep-alive
		return nil, fmt.Errorf("github compare api returned %d for %s...%s", resp.StatusCode, shortSHA(base), shortSHA(head))
	}

	var cmp compareResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&cmp); err != nil {
		return nil, fmt.Errorf("decoding compare response: %w", err)
	}

	var added, removed int
	for _, f := range cmp.Files {
		added += f.Additions
		removed += f.Deletions
	}

	return &DiffStats{
		LinesAdded:   added,
		LinesRemoved: removed,
		FilesChanged: len(cmp.Files),
	}, nil
}

// shortSHA returns the first 7 characters of a SHA, or the full string if shorter.
func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

// commitResponse represents a single commit from the GitHub Commits API.
type commitResponse struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
		Author  struct {
			Date time.Time `json:"date"`
		} `json:"author"`
	} `json:"commit"`
}

// RecentCommits lists commits for the configured repo since the given time.
func (g *Client) RecentCommits(ctx context.Context, since time.Time) ([]Commit, error) {
	return g.CommitsForRepo(ctx, g.repo, since)
}

// CommitsForRepo lists commits for an arbitrary repo since the given time using the GitHub Commits API.
func (g *Client) CommitsForRepo(ctx context.Context, repo string, since time.Time) ([]Commit, error) {
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/commits?since=%s&per_page=100",
		repo, since.Format(time.RFC3339))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching commits: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // drain for keep-alive
		return nil, fmt.Errorf("github api returned %d for commits", resp.StatusCode)
	}

	var raw []commitResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding commits: %w", err)
	}

	commits := make([]Commit, len(raw))
	for i, r := range raw {
		// Take only the first line of the commit message.
		msg := r.Commit.Message
		if idx := strings.IndexByte(msg, '\n'); idx > 0 {
			msg = msg[:idx]
		}
		sha := r.SHA
		if len(sha) > 7 {
			sha = sha[:7]
		}
		commits[i] = Commit{
			SHA:     sha,
			Message: msg,
			Date:    r.Commit.Author.Date,
		}
	}
	return commits, nil
}
