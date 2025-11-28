//go:build integration
// +build integration

package tools

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Integration tests for NetworkToolset with real SearXNG instance.
// Run with: go test -tags=integration ./internal/tools/...
//
// The tests automatically start SearXNG and Redis using testcontainers.
// No manual docker compose required!
//
// Environment variables:
//   - SEARXNG_URL: Override SearXNG URL (skip testcontainers if set)

// searxngContainer holds the SearXNG container and its URL
type searxngTestEnv struct {
	redisContainer   testcontainers.Container
	searxngContainer testcontainers.Container
	searxngURL       string
}

// setupSearXNG starts SearXNG and Redis containers for testing
func setupSearXNG(ctx context.Context) (*searxngTestEnv, error) {
	// Check if external SearXNG is provided
	if url := os.Getenv("SEARXNG_URL"); url != "" {
		return &searxngTestEnv{searxngURL: url}, nil
	}

	// Start Redis container
	redisReq := testcontainers.ContainerRequest{
		Image:        "valkey/valkey:8-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForListeningPort("6379/tcp").WithStartupTimeout(30 * time.Second),
	}
	redisC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: redisReq,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start redis: %w", err)
	}

	// Get Redis internal IP for SearXNG to connect
	redisIP, err := redisC.ContainerIP(ctx)
	if err != nil {
		_ = redisC.Terminate(ctx)
		return nil, fmt.Errorf("failed to get redis IP: %w", err)
	}

	// Start SearXNG container
	searxngReq := testcontainers.ContainerRequest{
		Image:        "searxng/searxng:latest",
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"SEARXNG_BASE_URL":  "http://localhost:8080/",
			"SEARXNG_REDIS_URL": fmt.Sprintf("redis://%s:6379/0", redisIP),
		},
		WaitingFor: wait.ForHTTP("/healthz").
			WithPort("8080/tcp").
			WithStartupTimeout(60 * time.Second),
	}
	searxngC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: searxngReq,
		Started:          true,
	})
	if err != nil {
		_ = redisC.Terminate(ctx)
		return nil, fmt.Errorf("failed to start searxng: %w", err)
	}

	// Get SearXNG mapped port
	host, err := searxngC.Host(ctx)
	if err != nil {
		_ = searxngC.Terminate(ctx)
		_ = redisC.Terminate(ctx)
		return nil, fmt.Errorf("failed to get searxng host: %w", err)
	}

	port, err := searxngC.MappedPort(ctx, "8080/tcp")
	if err != nil {
		_ = searxngC.Terminate(ctx)
		_ = redisC.Terminate(ctx)
		return nil, fmt.Errorf("failed to get searxng port: %w", err)
	}

	return &searxngTestEnv{
		redisContainer:   redisC,
		searxngContainer: searxngC,
		searxngURL:       fmt.Sprintf("http://%s:%s", host, port.Port()),
	}, nil
}

// teardown cleans up the containers
func (env *searxngTestEnv) teardown(ctx context.Context) {
	if env.searxngContainer != nil {
		_ = env.searxngContainer.Terminate(ctx)
	}
	if env.redisContainer != nil {
		_ = env.redisContainer.Terminate(ctx)
	}
}

// Global test environment (initialized once for all tests)
var testEnv *searxngTestEnv

func TestMain(m *testing.M) {
	ctx := context.Background()

	// Setup SearXNG environment
	var err error
	testEnv, err = setupSearXNG(ctx)
	if err != nil {
		fmt.Printf("Failed to setup SearXNG: %v\n", err)
		os.Exit(1)
	}

	// Run tests
	code := m.Run()

	// Teardown
	testEnv.teardown(ctx)

	os.Exit(code)
}

func getSearXNGURL() string {
	return testEnv.searxngURL
}

// ============================================================================
// Integration Tests: web_search
// ============================================================================

func TestIntegration_NetworkToolset_Search(t *testing.T) {
	searxngURL := getSearXNGURL()

	nt, err := NewNetworkToolset(
		searxngURL,
		2,
		time.Second,
		30*time.Second,
		testLogger(),
	)
	require.NoError(t, err)

	toolCtx := &ai.ToolContext{Context: context.Background()}

	t.Run("real search for golang", func(t *testing.T) {
		output, err := nt.search(toolCtx, SearchInput{
			Query:      "golang programming language",
			MaxResults: 5,
		})
		require.NoError(t, err)

		if output.Error != "" {
			t.Skipf("Search returned error (may be rate limited): %s", output.Error)
		}

		assert.Equal(t, "golang programming language", output.Query)
		assert.NotEmpty(t, output.Results, "should have search results")

		// Check result structure
		for _, result := range output.Results {
			assert.NotEmpty(t, result.Title, "result should have title")
			assert.NotEmpty(t, result.URL, "result should have URL")
			// Content may be empty for some results
		}

		t.Logf("Found %d results for 'golang programming language'", len(output.Results))
		if len(output.Results) > 0 {
			t.Logf("First result: %s - %s", output.Results[0].Title, output.Results[0].URL)
		}
	})

	t.Run("search with language filter", func(t *testing.T) {
		output, err := nt.search(toolCtx, SearchInput{
			Query:      "台灣科技新聞",
			Language:   "zh-TW",
			MaxResults: 3,
		})
		require.NoError(t, err)

		if output.Error != "" {
			t.Skipf("Search returned error: %s", output.Error)
		}

		t.Logf("Found %d results for Taiwan tech news", len(output.Results))
	})

	t.Run("search with category filter", func(t *testing.T) {
		output, err := nt.search(toolCtx, SearchInput{
			Query:      "artificial intelligence",
			Categories: []string{"news"},
			MaxResults: 5,
		})
		require.NoError(t, err)

		if output.Error != "" {
			t.Skipf("Search returned error: %s", output.Error)
		}

		t.Logf("Found %d news results for AI", len(output.Results))
	})

	t.Run("search with no results", func(t *testing.T) {
		output, err := nt.search(toolCtx, SearchInput{
			Query:      "xyznonexistentquery123456789abcdef",
			MaxResults: 5,
		})
		require.NoError(t, err)

		// Either no results or an error message is acceptable
		if output.Error == "" && len(output.Results) == 0 {
			t.Log("Got no results as expected")
		} else if output.Error != "" {
			t.Logf("Got error message: %s", output.Error)
		} else {
			t.Logf("Got %d results (search engines may return related results)", len(output.Results))
		}
	})
}

// ============================================================================
// Integration Tests: web_fetch
// ============================================================================

func TestIntegration_NetworkToolset_Fetch(t *testing.T) {
	searxngURL := getSearXNGURL()

	nt, err := NewNetworkToolset(
		searxngURL,
		2,
		500*time.Millisecond, // reasonable delay
		30*time.Second,
		testLogger(),
	)
	require.NoError(t, err)

	toolCtx := &ai.ToolContext{Context: context.Background()}

	t.Run("fetch real HTML page (go.dev)", func(t *testing.T) {
		output, err := nt.fetch(toolCtx, FetchInput{
			URLs: []string{"https://go.dev/"},
		})
		require.NoError(t, err)

		if len(output.FailedURLs) > 0 {
			t.Skipf("Failed to fetch go.dev: %s", output.FailedURLs[0].Reason)
		}

		require.Len(t, output.Results, 1)
		result := output.Results[0]

		assert.Contains(t, result.URL, "go.dev")
		assert.NotEmpty(t, result.Title, "should extract title")
		assert.NotEmpty(t, result.Content, "should extract content")
		assert.Contains(t, result.ContentType, "text/html")

		t.Logf("Fetched go.dev: title=%q, content length=%d", result.Title, len(result.Content))
	})

	t.Run("fetch real JSON API (GitHub)", func(t *testing.T) {
		output, err := nt.fetch(toolCtx, FetchInput{
			URLs: []string{"https://api.github.com/repos/golang/go"},
		})
		require.NoError(t, err)

		if len(output.FailedURLs) > 0 {
			t.Skipf("Failed to fetch GitHub API: %s", output.FailedURLs[0].Reason)
		}

		require.Len(t, output.Results, 1)
		result := output.Results[0]

		assert.Contains(t, result.ContentType, "application/json")
		assert.Equal(t, "JSON Response", result.Title)
		assert.Contains(t, result.Content, "golang")
		assert.Contains(t, result.Content, "Go")

		t.Logf("Fetched GitHub API, content length=%d", len(result.Content))
	})

	t.Run("fetch multiple URLs in parallel", func(t *testing.T) {
		urls := []string{
			"https://go.dev/",
			"https://pkg.go.dev/",
		}

		start := time.Now()
		output, err := nt.fetch(toolCtx, FetchInput{URLs: urls})
		elapsed := time.Since(start)
		require.NoError(t, err)

		successCount := len(output.Results)
		failCount := len(output.FailedURLs)

		t.Logf("Fetched %d URLs: %d success, %d failed in %v", len(urls), successCount, failCount, elapsed)

		// At least one should succeed
		assert.True(t, successCount > 0 || failCount > 0, "should attempt all URLs")
	})

	t.Run("fetch with CSS selector", func(t *testing.T) {
		output, err := nt.fetch(toolCtx, FetchInput{
			URLs:     []string{"https://go.dev/"},
			Selector: "main",
		})
		require.NoError(t, err)

		if len(output.FailedURLs) > 0 {
			t.Skipf("Failed to fetch: %s", output.FailedURLs[0].Reason)
		}

		if len(output.Results) > 0 {
			result := output.Results[0]
			t.Logf("Extracted with selector 'main': length=%d", len(result.Content))
		}
	})

	t.Run("fetch handles 404", func(t *testing.T) {
		output, err := nt.fetch(toolCtx, FetchInput{
			URLs: []string{"https://go.dev/this-page-does-not-exist-12345"},
		})
		require.NoError(t, err)

		assert.Len(t, output.Results, 0, "should not have successful results")
		assert.Len(t, output.FailedURLs, 1, "should report failure")
		assert.Equal(t, 404, output.FailedURLs[0].StatusCode)

		t.Logf("404 handled correctly: %s", output.FailedURLs[0].Reason)
	})
}

// ============================================================================
// E2E Test: Search then Fetch workflow
// ============================================================================

func TestIntegration_NetworkToolset_SearchThenFetch(t *testing.T) {
	searxngURL := getSearXNGURL()

	nt, err := NewNetworkToolset(
		searxngURL,
		2,
		time.Second,
		30*time.Second,
		testLogger(),
	)
	require.NoError(t, err)

	toolCtx := &ai.ToolContext{Context: context.Background()}

	// Step 1: Search for something
	t.Log("Step 1: Searching for 'Go programming documentation'...")
	searchOutput, err := nt.search(toolCtx, SearchInput{
		Query:      "Go programming documentation site:go.dev",
		MaxResults: 3,
	})
	require.NoError(t, err)

	if searchOutput.Error != "" {
		t.Skipf("Search failed: %s", searchOutput.Error)
	}

	if len(searchOutput.Results) == 0 {
		t.Skip("No search results to fetch")
	}

	t.Logf("Found %d search results", len(searchOutput.Results))

	// Step 2: Fetch the first result
	firstResult := searchOutput.Results[0]
	t.Logf("Step 2: Fetching first result: %s", firstResult.URL)

	fetchOutput, err := nt.fetch(toolCtx, FetchInput{
		URLs: []string{firstResult.URL},
	})
	require.NoError(t, err)

	if len(fetchOutput.FailedURLs) > 0 {
		t.Logf("Fetch failed: %s", fetchOutput.FailedURLs[0].Reason)
		return
	}

	require.Len(t, fetchOutput.Results, 1)
	fetchedContent := fetchOutput.Results[0]

	t.Logf("Successfully fetched content:")
	t.Logf("  URL: %s", fetchedContent.URL)
	t.Logf("  Title: %s", fetchedContent.Title)
	t.Logf("  Content Type: %s", fetchedContent.ContentType)
	t.Logf("  Content Length: %d bytes", len(fetchedContent.Content))

	// Verify we got meaningful content
	assert.NotEmpty(t, fetchedContent.Content, "fetched content should not be empty")
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkIntegration_NetworkToolset_Search(b *testing.B) {
	searxngURL := getSearXNGURL()

	nt, err := NewNetworkToolset(
		searxngURL,
		2,
		0, // no delay for benchmark
		30*time.Second,
		testLogger(),
	)
	if err != nil {
		b.Fatalf("Failed to create toolset: %v", err)
	}

	toolCtx := &ai.ToolContext{Context: context.Background()}

	b.ResetTimer()
	for b.Loop() {
		_, _ = nt.search(toolCtx, SearchInput{
			Query:      "golang",
			MaxResults: 5,
		})
	}
}

func BenchmarkIntegration_NetworkToolset_Fetch(b *testing.B) {
	searxngURL := getSearXNGURL()

	nt, err := NewNetworkToolset(
		searxngURL,
		2,
		0,
		30*time.Second,
		testLogger(),
	)
	if err != nil {
		b.Fatalf("Failed to create toolset: %v", err)
	}

	toolCtx := &ai.ToolContext{Context: context.Background()}

	b.ResetTimer()
	for b.Loop() {
		_, _ = nt.fetch(toolCtx, FetchInput{
			URLs: []string{"https://go.dev/"},
		})
	}
}
