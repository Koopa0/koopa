package pipeline

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

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
