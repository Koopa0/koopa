package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// networkTestSessionID creates a SessionID for testing in network_test.go
func networkTestSessionID(t *testing.T, id string) agent.SessionID {
	t.Helper()
	s, err := agent.NewSessionID(id)
	require.NoError(t, err)
	return s
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNetworkToolset_NewNetworkToolset(t *testing.T) {
	t.Parallel()

	t.Run("successful creation with all params", func(t *testing.T) {
		t.Parallel()
		nt, err := NewNetworkToolset(
			"http://searxng:8080",
			2,
			time.Second,
			30*time.Second,
			testLogger(),
		)
		require.NoError(t, err)
		assert.NotNil(t, nt)
		assert.Equal(t, NetworkToolsetName, nt.Name())
	})

	t.Run("successful creation with defaults", func(t *testing.T) {
		t.Parallel()
		nt, err := NewNetworkToolset(
			"http://searxng:8080",
			0, // use default parallelism
			0, // use default delay
			0, // use default timeout
			testLogger(),
		)
		require.NoError(t, err)
		assert.NotNil(t, nt)
	})

	t.Run("empty search base URL fails", func(t *testing.T) {
		t.Parallel()
		nt, err := NewNetworkToolset("", 0, 0, 0, testLogger())
		assert.Error(t, err)
		assert.Nil(t, nt)
		assert.Contains(t, err.Error(), "search base URL is required")
	})

	t.Run("nil logger fails", func(t *testing.T) {
		t.Parallel()
		nt, err := NewNetworkToolset("http://searxng:8080", 0, 0, 0, nil)
		assert.Error(t, err)
		assert.Nil(t, nt)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

// ============================================================================
// Tools List Tests
// ============================================================================

func TestNetworkToolset_Tools(t *testing.T) {
	t.Parallel()

	nt, err := NewNetworkToolset("http://searxng:8080", 0, 0, 0, testLogger())
	require.NoError(t, err)

	ctx := agent.NewInvocationContext(
		context.Background(),
		"test-inv",
		"main",
		networkTestSessionID(t, "test-session"),
		"test-agent",
	)

	tools, err := nt.Tools(ctx)
	require.NoError(t, err)
	require.Len(t, tools, 2, "NetworkToolset should define exactly 2 tools")

	// Verify tool names
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolNames[tool.Name()] = true
	}
	assert.True(t, toolNames[ToolWebSearch], "should have web_search tool")
	assert.True(t, toolNames[ToolWebFetch], "should have web_fetch tool")
}

// ============================================================================
// web_search Tests
// ============================================================================

func TestNetworkToolset_Search(t *testing.T) {
	t.Parallel()

	toolCtx := &ai.ToolContext{Context: context.Background()}

	t.Run("successful search", func(t *testing.T) {
		t.Parallel()

		// Create mock SearXNG server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/search", r.URL.Path)
			assert.Equal(t, "golang tutorial", r.URL.Query().Get("q"))
			assert.Equal(t, "json", r.URL.Query().Get("format"))

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"results": []map[string]any{
					{
						"title":   "Go Tutorial",
						"url":     "https://go.dev/doc/tutorial",
						"content": "Learn Go programming",
						"engine":  "google",
					},
					{
						"title":   "Go by Example",
						"url":     "https://gobyexample.com",
						"content": "Hands-on introduction to Go",
						"engine":  "duckduckgo",
					},
				},
			})
		}))
		defer server.Close()

		nt, err := NewNetworkToolset(server.URL, 0, 0, 0, testLogger())
		require.NoError(t, err)

		output, err := nt.search(toolCtx, SearchInput{Query: "golang tutorial"})
		require.NoError(t, err)
		assert.Empty(t, output.Error)
		assert.Equal(t, "golang tutorial", output.Query)
		assert.Len(t, output.Results, 2)
		assert.Equal(t, "Go Tutorial", output.Results[0].Title)
		assert.Equal(t, "https://go.dev/doc/tutorial", output.Results[0].URL)
	})

	t.Run("search with categories and language", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "news,science", r.URL.Query().Get("categories"))
			assert.Equal(t, "zh-TW", r.URL.Query().Get("language"))

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"results": []map[string]any{
					{"title": "Result", "url": "https://example.com", "content": "Content"},
				},
			})
		}))
		defer server.Close()

		nt, err := NewNetworkToolset(server.URL, 0, 0, 0, testLogger())
		require.NoError(t, err)

		output, err := nt.search(toolCtx, SearchInput{
			Query:      "test",
			Categories: []string{"news", "science"},
			Language:   "zh-TW",
		})
		require.NoError(t, err)
		assert.Empty(t, output.Error)
	})

	t.Run("search with max results limit", func(t *testing.T) {
		t.Parallel()

		// Return 20 results
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			results := make([]map[string]any, 20)
			for i := 0; i < 20; i++ {
				results[i] = map[string]any{
					"title":   "Result",
					"url":     "https://example.com",
					"content": "Content",
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		}))
		defer server.Close()

		nt, err := NewNetworkToolset(server.URL, 0, 0, 0, testLogger())
		require.NoError(t, err)

		output, err := nt.search(toolCtx, SearchInput{Query: "test", MaxResults: 5})
		require.NoError(t, err)
		assert.Len(t, output.Results, 5)
	})

	t.Run("search no results", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
		}))
		defer server.Close()

		nt, err := NewNetworkToolset(server.URL, 0, 0, 0, testLogger())
		require.NoError(t, err)

		output, err := nt.search(toolCtx, SearchInput{Query: "nonexistent query xyz"})
		require.NoError(t, err)
		assert.Equal(t, "No results found for this query.", output.Error)
		assert.Empty(t, output.Results)
	})

	t.Run("search rate limited", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		nt, err := NewNetworkToolset(server.URL, 0, 0, 0, testLogger())
		require.NoError(t, err)

		output, err := nt.search(toolCtx, SearchInput{Query: "test"})
		require.NoError(t, err)
		assert.Contains(t, output.Error, "rate limited")
	})

	t.Run("search server error", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		nt, err := NewNetworkToolset(server.URL, 0, 0, 0, testLogger())
		require.NoError(t, err)

		output, err := nt.search(toolCtx, SearchInput{Query: "test"})
		require.NoError(t, err)
		assert.Contains(t, output.Error, "temporarily unavailable")
	})
}

// ============================================================================
// web_fetch Tests
// ============================================================================

func TestNetworkToolset_Fetch(t *testing.T) {
	t.Parallel()

	toolCtx := &ai.ToolContext{Context: context.Background()}

	t.Run("fetch single HTML page", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`
				<!DOCTYPE html>
				<html>
				<head><title>Test Page</title></head>
				<body>
					<article>
						<h1>Test Article</h1>
						<p>This is test content for the article.</p>
					</article>
				</body>
				</html>
			`))
		}))
		defer server.Close()

		// Use ForTesting to skip SSRF checks for localhost test servers
		nt, err := NewNetworkToolsetForTesting("http://searxng:8080", 2, 100*time.Millisecond, 10*time.Second, testLogger())
		require.NoError(t, err)

		output, err := nt.fetch(toolCtx, FetchInput{URLs: []string{server.URL}})
		require.NoError(t, err)
		assert.Empty(t, output.FailedURLs)
		require.Len(t, output.Results, 1)
		assert.Equal(t, "text/html", output.Results[0].ContentType)
		assert.NotEmpty(t, output.Results[0].Content)
	})

	t.Run("fetch JSON API", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":   "test",
				"value":  123,
				"nested": map[string]any{"key": "value"},
			})
		}))
		defer server.Close()

		nt, err := NewNetworkToolsetForTesting("http://searxng:8080", 2, 100*time.Millisecond, 10*time.Second, testLogger())
		require.NoError(t, err)

		output, err := nt.fetch(toolCtx, FetchInput{URLs: []string{server.URL}})
		require.NoError(t, err)
		assert.Empty(t, output.FailedURLs)
		require.Len(t, output.Results, 1)
		assert.Contains(t, output.Results[0].ContentType, "application/json")
		assert.Equal(t, "JSON Response", output.Results[0].Title)
		// Should be pretty-printed
		assert.Contains(t, output.Results[0].Content, "\"name\": \"test\"")
	})

	t.Run("fetch plain text", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Plain text content\nLine 2"))
		}))
		defer server.Close()

		nt, err := NewNetworkToolsetForTesting("http://searxng:8080", 2, 100*time.Millisecond, 10*time.Second, testLogger())
		require.NoError(t, err)

		output, err := nt.fetch(toolCtx, FetchInput{URLs: []string{server.URL}})
		require.NoError(t, err)
		assert.Empty(t, output.FailedURLs)
		require.Len(t, output.Results, 1)
		assert.Equal(t, "Text Content", output.Results[0].Title)
		assert.Equal(t, "Plain text content\nLine 2", output.Results[0].Content)
	})

	t.Run("fetch multiple URLs", func(t *testing.T) {
		t.Parallel()

		server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Content from server 1"))
		}))
		defer server1.Close()

		server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Content from server 2"))
		}))
		defer server2.Close()

		nt, err := NewNetworkToolsetForTesting("http://searxng:8080", 2, 100*time.Millisecond, 10*time.Second, testLogger())
		require.NoError(t, err)

		output, err := nt.fetch(toolCtx, FetchInput{URLs: []string{server1.URL, server2.URL}})
		require.NoError(t, err)
		assert.Empty(t, output.FailedURLs)
		assert.Len(t, output.Results, 2)
	})

	t.Run("fetch with partial failure", func(t *testing.T) {
		t.Parallel()

		goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Good content"))
		}))
		defer goodServer.Close()

		badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer badServer.Close()

		nt, err := NewNetworkToolsetForTesting("http://searxng:8080", 2, 100*time.Millisecond, 10*time.Second, testLogger())
		require.NoError(t, err)

		output, err := nt.fetch(toolCtx, FetchInput{URLs: []string{goodServer.URL, badServer.URL}})
		require.NoError(t, err)
		assert.Len(t, output.Results, 1)
		assert.Len(t, output.FailedURLs, 1)
		// URL may have trailing slash added by Colly
		assert.Contains(t, output.FailedURLs[0].URL, badServer.URL)
		assert.Equal(t, 500, output.FailedURLs[0].StatusCode)
	})

	t.Run("fetch deduplicates URLs", func(t *testing.T) {
		t.Parallel()

		var callCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&callCount, 1)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Content"))
		}))
		defer server.Close()

		nt, err := NewNetworkToolsetForTesting("http://searxng:8080", 2, 100*time.Millisecond, 10*time.Second, testLogger())
		require.NoError(t, err)

		output, err := nt.fetch(toolCtx, FetchInput{URLs: []string{server.URL, server.URL, server.URL}})
		require.NoError(t, err)
		assert.Len(t, output.Results, 1, "should deduplicate URLs")
		assert.Equal(t, int32(1), atomic.LoadInt32(&callCount), "should only call server once")
	})

	t.Run("fetch empty URLs fails", func(t *testing.T) {
		t.Parallel()

		nt, err := NewNetworkToolset("http://searxng:8080", 0, 0, 0, testLogger())
		require.NoError(t, err)

		_, err = nt.fetch(toolCtx, FetchInput{URLs: []string{}})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one URL is required")
	})

	t.Run("fetch too many URLs fails", func(t *testing.T) {
		t.Parallel()

		nt, err := NewNetworkToolset("http://searxng:8080", 0, 0, 0, testLogger())
		require.NoError(t, err)

		urls := make([]string, MaxURLsPerRequest+1)
		for i := range urls {
			urls[i] = "https://example.com"
		}

		_, err = nt.fetch(toolCtx, FetchInput{URLs: urls})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "maximum")
	})
}

// ============================================================================
// Tool Metadata Tests
// ============================================================================

func TestNetworkToolset_ToolMetadata(t *testing.T) {
	t.Parallel()

	nt, err := NewNetworkToolset("http://searxng:8080", 0, 0, 0, testLogger())
	require.NoError(t, err)

	ctx := agent.NewInvocationContext(
		context.Background(),
		"test-inv",
		"main",
		networkTestSessionID(t, "test-session"),
		"test-agent",
	)

	tools, err := nt.Tools(ctx)
	require.NoError(t, err)
	require.Len(t, tools, 2)

	// Find tools by name
	var searchTool, fetchTool Tool
	for _, tool := range tools {
		switch tool.Name() {
		case ToolWebSearch:
			searchTool = tool
		case ToolWebFetch:
			fetchTool = tool
		}
	}

	// web_search metadata
	require.NotNil(t, searchTool)
	assert.NotEmpty(t, searchTool.Description())
	assert.Contains(t, searchTool.Description(), "Search the web")
	assert.True(t, searchTool.IsLongRunning())

	// web_fetch metadata
	require.NotNil(t, fetchTool)
	assert.NotEmpty(t, fetchTool.Description())
	assert.Contains(t, fetchTool.Description(), "Fetch")
	assert.Contains(t, fetchTool.Description(), "HTML")
	assert.Contains(t, fetchTool.Description(), "JSON")
	assert.Contains(t, fetchTool.Description(), "JavaScript") // SPA warning
	assert.True(t, fetchTool.IsLongRunning())
}

// ============================================================================
// SSRF Protection Tests
// ============================================================================

// TestNetworkToolset_SSRFProtection tests that SSRF bypass attempts are blocked.
// Security: Ensures the toolset properly validates URLs to prevent SSRF attacks.
func TestNetworkToolset_SSRFProtection(t *testing.T) {
	t.Parallel()

	toolCtx := &ai.ToolContext{Context: context.Background()}

	// Use regular NewNetworkToolset (NOT ForTesting) to enable SSRF checks
	nt, err := NewNetworkToolset("http://searxng:8080", 2, 100*time.Millisecond, 10*time.Second, testLogger())
	require.NoError(t, err)

	t.Run("blocks localhost", func(t *testing.T) {
		t.Parallel()

		localURLs := []string{
			"http://localhost/admin",
			"http://127.0.0.1/secret",
			"http://0.0.0.0/",
		}

		for _, url := range localURLs {
			output, err := nt.fetch(toolCtx, FetchInput{URLs: []string{url}})
			// Should either return error or have URL in failed list
			if err == nil {
				assert.Len(t, output.FailedURLs, 1, "localhost URL should be blocked: %s", url)
			}
		}
	})

	t.Run("blocks cloud metadata endpoints", func(t *testing.T) {
		t.Parallel()

		metadataURLs := []string{
			"http://169.254.169.254/latest/meta-data/",
			"http://metadata.google.internal/computeMetadata/v1/",
		}

		for _, url := range metadataURLs {
			output, err := nt.fetch(toolCtx, FetchInput{URLs: []string{url}})
			if err == nil {
				assert.Len(t, output.FailedURLs, 1, "metadata URL should be blocked: %s", url)
			}
		}
	})

	t.Run("blocks private IP ranges", func(t *testing.T) {
		t.Parallel()

		privateURLs := []string{
			"http://10.0.0.1/internal",
			"http://172.16.0.1/admin",
			"http://192.168.1.1/router",
		}

		for _, url := range privateURLs {
			output, err := nt.fetch(toolCtx, FetchInput{URLs: []string{url}})
			if err == nil {
				assert.Len(t, output.FailedURLs, 1, "private IP URL should be blocked: %s", url)
			}
		}
	})

	t.Run("blocks dangerous protocols", func(t *testing.T) {
		t.Parallel()

		dangerousURLs := []string{
			"file:///etc/passwd",
			"ftp://internal-server/files",
			"gopher://localhost:25/",
		}

		for _, url := range dangerousURLs {
			output, err := nt.fetch(toolCtx, FetchInput{URLs: []string{url}})
			if err == nil {
				assert.Len(t, output.FailedURLs, 1, "dangerous protocol should be blocked: %s", url)
			}
		}
	})

	t.Run("blocks URL with userinfo bypass attempt", func(t *testing.T) {
		t.Parallel()

		// SSRF bypass attempt: http://evil.com@127.0.0.1/
		bypassURLs := []string{
			"http://user:pass@127.0.0.1/",
			"http://attacker.com@localhost/admin",
		}

		for _, url := range bypassURLs {
			output, err := nt.fetch(toolCtx, FetchInput{URLs: []string{url}})
			if err == nil {
				assert.Len(t, output.FailedURLs, 1, "userinfo bypass should be blocked: %s", url)
			}
		}
	})
}
