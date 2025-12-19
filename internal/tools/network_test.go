package tools

import (
	"testing"
	"time"
)

func TestNetworkTools_Constructor(t *testing.T) {
	t.Run("valid inputs", func(t *testing.T) {
		cfg := NetworkConfig{
			SearchBaseURL:    "http://localhost:8080",
			FetchParallelism: 2,
			FetchDelay:       time.Second,
			FetchTimeout:     30 * time.Second,
		}

		nt, err := NewNetworkTools(cfg, testLogger())
		if err != nil {
			t.Errorf("NewNetworkTools() error = %v, want nil", err)
		}
		if nt == nil {
			t.Error("NewNetworkTools() returned nil, want non-nil")
		}
	})

	t.Run("empty search URL", func(t *testing.T) {
		cfg := NetworkConfig{
			SearchBaseURL: "",
		}

		nt, err := NewNetworkTools(cfg, testLogger())
		if err == nil {
			t.Error("NewNetworkTools() error = nil, want error")
		}
		if nt != nil {
			t.Error("NewNetworkTools() returned non-nil, want nil")
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		cfg := NetworkConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		nt, err := NewNetworkTools(cfg, nil)
		if err == nil {
			t.Error("NewNetworkTools() error = nil, want error")
		}
		if nt != nil {
			t.Error("NewNetworkTools() returned non-nil, want nil")
		}
	})

	t.Run("defaults applied", func(t *testing.T) {
		cfg := NetworkConfig{
			SearchBaseURL: "http://localhost:8080",
			// Leave other fields as zero values
		}

		nt, err := NewNetworkTools(cfg, testLogger())
		if err != nil {
			t.Errorf("NewNetworkTools() error = %v, want nil", err)
		}
		if nt == nil {
			t.Fatal("NewNetworkTools() returned nil")
		}
		// Verify defaults were applied (internal fields not accessible, but no error means success)
	})
}

func TestNetworkToolConstants(t *testing.T) {
	expectedNames := map[string]string{
		"ToolWebSearch": "web_search",
		"ToolWebFetch":  "web_fetch",
	}

	if ToolWebSearch != expectedNames["ToolWebSearch"] {
		t.Errorf("ToolWebSearch = %q, want %q", ToolWebSearch, expectedNames["ToolWebSearch"])
	}
	if ToolWebFetch != expectedNames["ToolWebFetch"] {
		t.Errorf("ToolWebFetch = %q, want %q", ToolWebFetch, expectedNames["ToolWebFetch"])
	}
}

func TestNetworkConfigConstants(t *testing.T) {
	// Verify content limits
	if MaxURLsPerRequest != 10 {
		t.Errorf("MaxURLsPerRequest = %d, want 10", MaxURLsPerRequest)
	}
	if MaxContentLength != 50000 {
		t.Errorf("MaxContentLength = %d, want 50000", MaxContentLength)
	}
	if MaxSearchResults != 50 {
		t.Errorf("MaxSearchResults = %d, want 50", MaxSearchResults)
	}
	if DefaultSearchResults != 10 {
		t.Errorf("DefaultSearchResults = %d, want 10", DefaultSearchResults)
	}
}

func TestSearchInput(t *testing.T) {
	input := SearchInput{
		Query:      "test query",
		Categories: []string{"general", "news"},
		Language:   "en",
		MaxResults: 20,
	}
	if input.Query != "test query" {
		t.Errorf("SearchInput.Query = %q, want %q", input.Query, "test query")
	}
	if len(input.Categories) != 2 {
		t.Errorf("SearchInput.Categories length = %d, want 2", len(input.Categories))
	}
	if input.Language != "en" {
		t.Errorf("SearchInput.Language = %q, want %q", input.Language, "en")
	}
	if input.MaxResults != 20 {
		t.Errorf("SearchInput.MaxResults = %d, want 20", input.MaxResults)
	}
}

func TestFetchInput(t *testing.T) {
	input := FetchInput{
		URLs:     []string{"https://example.com", "https://test.com"},
		Selector: "article",
	}
	if len(input.URLs) != 2 {
		t.Errorf("FetchInput.URLs length = %d, want 2", len(input.URLs))
	}
	if input.Selector != "article" {
		t.Errorf("FetchInput.Selector = %q, want %q", input.Selector, "article")
	}
}

func TestSearchOutput(t *testing.T) {
	output := SearchOutput{
		Results: []SearchResult{
			{
				Title:   "Test",
				URL:     "https://example.com",
				Content: "Test content",
				Engine:  "google",
			},
		},
		Query: "test",
	}
	if len(output.Results) != 1 {
		t.Errorf("SearchOutput.Results length = %d, want 1", len(output.Results))
	}
	if output.Query != "test" {
		t.Errorf("SearchOutput.Query = %q, want %q", output.Query, "test")
	}
}

func TestFetchOutput(t *testing.T) {
	output := FetchOutput{
		Results: []FetchResult{
			{
				URL:         "https://example.com",
				Title:       "Example",
				Content:     "Content",
				ContentType: "text/html",
			},
		},
		FailedURLs: []FailedURL{
			{
				URL:        "https://failed.com",
				Reason:     "connection refused",
				StatusCode: 503,
			},
		},
	}
	if len(output.Results) != 1 {
		t.Errorf("FetchOutput.Results length = %d, want 1", len(output.Results))
	}
	if len(output.FailedURLs) != 1 {
		t.Errorf("FetchOutput.FailedURLs length = %d, want 1", len(output.FailedURLs))
	}
}

func TestSearchResult(t *testing.T) {
	result := SearchResult{
		Title:       "Test Title",
		URL:         "https://example.com",
		Content:     "Test content",
		Engine:      "google",
		PublishedAt: "2024-01-01",
	}
	if result.Title != "Test Title" {
		t.Errorf("SearchResult.Title = %q, want %q", result.Title, "Test Title")
	}
	if result.URL != "https://example.com" {
		t.Errorf("SearchResult.URL = %q, want %q", result.URL, "https://example.com")
	}
	if result.Engine != "google" {
		t.Errorf("SearchResult.Engine = %q, want %q", result.Engine, "google")
	}
	if result.PublishedAt != "2024-01-01" {
		t.Errorf("SearchResult.PublishedAt = %q, want %q", result.PublishedAt, "2024-01-01")
	}
}

func TestFetchResult(t *testing.T) {
	result := FetchResult{
		URL:         "https://example.com",
		Title:       "Example",
		Content:     "Content",
		ContentType: "text/html",
	}
	if result.URL != "https://example.com" {
		t.Errorf("FetchResult.URL = %q, want %q", result.URL, "https://example.com")
	}
	if result.ContentType != "text/html" {
		t.Errorf("FetchResult.ContentType = %q, want %q", result.ContentType, "text/html")
	}
}

func TestFailedURL(t *testing.T) {
	failed := FailedURL{
		URL:        "https://failed.com",
		Reason:     "timeout",
		StatusCode: 504,
	}
	if failed.URL != "https://failed.com" {
		t.Errorf("FailedURL.URL = %q, want %q", failed.URL, "https://failed.com")
	}
	if failed.Reason != "timeout" {
		t.Errorf("FailedURL.Reason = %q, want %q", failed.Reason, "timeout")
	}
	if failed.StatusCode != 504 {
		t.Errorf("FailedURL.StatusCode = %d, want 504", failed.StatusCode)
	}
}
