package pipeline

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

	"github.com/koopa0/blog-backend/internal/activity"
)

// ErrGitHubNotFound indicates a 404 from the GitHub API (permanent — file deleted or missing).
var ErrGitHubNotFound = errors.New("github: not found")

// Commit represents a single GitHub commit.
type Commit struct {
	SHA     string
	Message string
	Date    time.Time
}

// GitHub fetches file content from a GitHub repository using the GitHub API.
type GitHub struct {
	token  string
	repo   string // "owner/repo"
	client *http.Client
}

// NewGitHub returns a GitHub fetcher with a 15-second HTTP timeout.
func NewGitHub(token, repo string) *GitHub {
	return &GitHub{
		token: token,
		repo:  repo,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// githubFileResponse represents the GitHub Contents API response.
type githubFileResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// FileContent fetches the raw content of a file from the repository's default branch.
func (g *GitHub) FileContent(ctx context.Context, path string) ([]byte, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", g.repo, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching file: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on read-only HTTP response

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body) // drain for keep-alive
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("github %s: %w", path, ErrGitHubNotFound)
		}
		return nil, fmt.Errorf("github api returned %d for %s", resp.StatusCode, path)
	}

	var fileResp githubFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&fileResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
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

// githubDirEntry represents a single entry from the GitHub Contents API directory listing.
type githubDirEntry struct {
	Name string `json:"name"`
	Type string `json:"type"` // "file" or "dir"
}

// ListDirectory lists file names in a directory using the GitHub Contents API.
func (g *GitHub) ListDirectory(ctx context.Context, path string) ([]string, error) {
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", g.repo, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing directory: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on read-only HTTP response

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body) // drain for keep-alive
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("github directory %s: %w", path, ErrGitHubNotFound)
		}
		return nil, fmt.Errorf("github api returned %d for directory %s", resp.StatusCode, path)
	}

	var entries []githubDirEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
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

// githubCompareResponse represents the relevant fields from the GitHub Compare API.
type githubCompareResponse struct {
	TotalCommits int                 `json:"total_commits"`
	Files        []githubCompareFile `json:"files"`
}

// githubCompareFile represents a single file in a compare response.
type githubCompareFile struct {
	Additions int `json:"additions"`
	Deletions int `json:"deletions"`
}

// Compare fetches diff stats between two commits using the GitHub Compare API.
// repo is "owner/repo", base and head are commit SHAs.
func (g *GitHub) Compare(ctx context.Context, repo, base, head string) (*activity.DiffStats, error) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid repo format %q: expected owner/repo", repo)
	}
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/compare/%s...%s",
		url.PathEscape(parts[0]), url.PathEscape(parts[1]),
		url.PathEscape(base), url.PathEscape(head))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating compare request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching compare: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on read-only HTTP response

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body) // drain for keep-alive
		return nil, fmt.Errorf("github compare api returned %d for %s...%s", resp.StatusCode, shortSHA(base), shortSHA(head))
	}

	var cmp githubCompareResponse
	if err := json.NewDecoder(resp.Body).Decode(&cmp); err != nil {
		return nil, fmt.Errorf("decoding compare response: %w", err)
	}

	var added, removed int
	for _, f := range cmp.Files {
		added += f.Additions
		removed += f.Deletions
	}

	return &activity.DiffStats{
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

// githubCommitResponse represents a single commit from the GitHub Commits API.
type githubCommitResponse struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
		Author  struct {
			Date time.Time `json:"date"`
		} `json:"author"`
	} `json:"commit"`
}

// RecentCommits lists commits for the configured repo since the given time.
func (g *GitHub) RecentCommits(ctx context.Context, since time.Time) ([]Commit, error) {
	return g.CommitsForRepo(ctx, g.repo, since)
}

// CommitsForRepo lists commits for an arbitrary repo since the given time using the GitHub Commits API.
func (g *GitHub) CommitsForRepo(ctx context.Context, repo string, since time.Time) ([]Commit, error) {
	endpoint := fmt.Sprintf("https://api.github.com/repos/%s/commits?since=%s&per_page=100",
		repo, since.Format(time.RFC3339))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching commits: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on read-only HTTP response

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body) // drain for keep-alive
		return nil, fmt.Errorf("github api returned %d for commits", resp.StatusCode)
	}

	var raw []githubCommitResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
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
