package tools

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/security"
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
// Mock HTTP Validator (for testing success scenarios)
// ============================================================================

// mockHTTPValidator implements httpValidator interface for testing
// Follows Go best practices: consumer defines interface, tests use mock implementation
type mockHTTPValidator struct {
	validateErr     error
	client          *http.Client
	maxSize         int64
	allowedTestURLs map[string]bool
}

func (m *mockHTTPValidator) ValidateURL(url string) error {
	// Whitelist mechanism: allow test URLs
	if m.allowedTestURLs != nil && m.allowedTestURLs[url] {
		return nil
	}
	return m.validateErr
}

func (m *mockHTTPValidator) Client() *http.Client {
	if m.client != nil {
		return m.client
	}
	return &http.Client{}
}

func (m *mockHTTPValidator) MaxResponseSize() int64 {
	if m.maxSize > 0 {
		return m.maxSize
	}
	return 5 * 1024 * 1024 // 5MB default
}

// TestNetworkToolset_NewNetworkToolset tests NetworkToolset constructor
func TestNetworkToolset_NewNetworkToolset(t *testing.T) {
	t.Parallel()

	t.Run("successful creation", func(t *testing.T) {
		t.Parallel()
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, testLogger())
		require.NoError(t, err)
		assert.NotNil(t, nt)
		assert.Equal(t, NetworkToolsetName, nt.Name())
	})

	t.Run("nil http validator fails", func(t *testing.T) {
		t.Parallel()
		nt, err := NewNetworkToolset(nil, testLogger())
		assert.Error(t, err)
		assert.Nil(t, nt)
		assert.Contains(t, err.Error(), "http validator is required")
	})

	t.Run("nil logger fails", func(t *testing.T) {
		t.Parallel()
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, nil)
		assert.Error(t, err)
		assert.Nil(t, nt)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

// TestNetworkToolset_Tools tests tool list
func TestNetworkToolset_Tools(t *testing.T) {
	t.Parallel()

	httpVal := security.NewHTTP()
	nt, err := NewNetworkToolset(httpVal, testLogger())
	require.NoError(t, err)

	// Create invocation context
	ctx := agent.NewInvocationContext(
		context.Background(),
		"test-inv",
		"main",
		networkTestSessionID(t, "test-session"),
		"test-agent",
	)

	tools, err := nt.Tools(ctx)
	require.NoError(t, err)
	require.Len(t, tools, 1, "NetworkToolset should define exactly 1 tool")

	// Verify tool names
	toolNames := []string{"httpGet"}
	for _, tool := range tools {
		assert.Contains(t, toolNames, tool.Name())
	}
}

// TestNetworkToolset_HTTPGet tests httpGet tool
func TestNetworkToolset_HTTPGet(t *testing.T) {
	t.Parallel()

	// Create tool context
	toolCtx := &ai.ToolContext{Context: context.Background()}

	t.Run("successful GET request", func(t *testing.T) {
		// Create test server
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Hello, World!"))
		}))
		defer testServer.Close()

		// Create mock validator and allow test URL
		mockVal := &mockHTTPValidator{
			allowedTestURLs: map[string]bool{testServer.URL: true},
			client:          &http.Client{},
		}

		// Use mock implementation of httpValidator interface
		nt, err := NewNetworkToolset(mockVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: testServer.URL})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)

		dataMap, ok := result.Data.(map[string]any)
		require.True(t, ok)

		assert.Equal(t, testServer.URL, dataMap["url"])
		assert.Equal(t, http.StatusOK, dataMap["status"])
		assert.Equal(t, "Hello, World!", dataMap["body"])
	})

	t.Run("successful GET with different status code", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("Created"))
		}))
		defer testServer.Close()

		mockVal := &mockHTTPValidator{
			allowedTestURLs: map[string]bool{testServer.URL: true},
			client:          &http.Client{},
		}

		nt, err := NewNetworkToolset(mockVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: testServer.URL})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)

		dataMap, ok := result.Data.(map[string]any)
		require.True(t, ok)
		assert.Equal(t, http.StatusCreated, dataMap["status"])
		assert.Equal(t, "Created", dataMap["body"])
	})

	t.Run("empty response body", func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer testServer.Close()

		mockVal := &mockHTTPValidator{
			allowedTestURLs: map[string]bool{testServer.URL: true},
			client:          &http.Client{},
		}

		nt, err := NewNetworkToolset(mockVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: testServer.URL})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)

		dataMap, ok := result.Data.(map[string]any)
		require.True(t, ok)
		assert.Equal(t, http.StatusNoContent, dataMap["status"])
		assert.Equal(t, "", dataMap["body"])
	})

	t.Run("SSRF blocked - localhost", func(t *testing.T) {
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: "http://localhost:8080/test"})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
		assert.Contains(t, result.Error.Message, "security warning")
		assert.Contains(t, result.Error.Message, "SSRF")
	})

	t.Run("SSRF blocked - 127.0.0.1", func(t *testing.T) {
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: "http://127.0.0.1:8080/test"})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
		assert.Contains(t, result.Error.Message, "security warning")
	})

	t.Run("SSRF blocked - AWS metadata endpoint", func(t *testing.T) {
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: "http://169.254.169.254/latest/meta-data/"})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
		assert.Contains(t, result.Error.Message, "security warning")
	})

	t.Run("SSRF blocked - GCP metadata endpoint", func(t *testing.T) {
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: "http://metadata.google.internal/computeMetadata/v1/"})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
		assert.Contains(t, result.Error.Message, "security warning")
	})

	t.Run("SSRF blocked - private IP 192.168.x.x", func(t *testing.T) {
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: "http://192.168.1.1/"})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
		assert.Contains(t, result.Error.Message, "security warning")
	})

	t.Run("SSRF blocked - private IP 10.x.x.x", func(t *testing.T) {
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: "http://10.0.0.1/"})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
		assert.Contains(t, result.Error.Message, "security warning")
	})

	t.Run("SSRF blocked - private IP 172.16.x.x", func(t *testing.T) {
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: "http://172.16.0.1/"})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
		assert.Contains(t, result.Error.Message, "security warning")
	})

	t.Run("invalid URL", func(t *testing.T) {
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: "not-a-valid-url"})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
	})

	t.Run("disallowed protocol - ftp", func(t *testing.T) {
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: "ftp://example.com/file.txt"})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
		assert.Contains(t, result.Error.Message, "security warning")
	})

	t.Run("disallowed protocol - file", func(t *testing.T) {
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: "file:///etc/passwd"})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.Equal(t, ErrCodeSecurity, result.Error.Code)
	})

	t.Run("network error - invalid hostname", func(t *testing.T) {
		httpVal := security.NewHTTP()
		nt, err := NewNetworkToolset(httpVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: "http://invalid-hostname-that-does-not-exist-12345.com/"})
		require.NoError(t, err)
		// This could be either security error (DNS resolution fails during validation)
		// or network error (if validation passes but connection fails)
		assert.Equal(t, StatusError, result.Status)
		assert.True(t,
			result.Error.Code == ErrCodeSecurity || result.Error.Code == ErrCodeNetwork,
			"Expected security or network error code",
		)
	})
}

// TestNetworkToolset_HTTPGet_ResponseSizeLimit tests response size limits
func TestNetworkToolset_HTTPGet_ResponseSizeLimit(t *testing.T) {
	t.Parallel()

	toolCtx := &ai.ToolContext{Context: context.Background()}

	t.Run("response within size limit", func(t *testing.T) {
		// Create 1MB response (well within 5MB limit)
		largeData := make([]byte, 1024*1024) // 1 MB
		for i := range largeData {
			largeData[i] = 'A'
		}

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(largeData)
		}))
		defer testServer.Close()

		mockVal := &mockHTTPValidator{
			allowedTestURLs: map[string]bool{testServer.URL: true},
			client:          &http.Client{},
		}

		nt, err := NewNetworkToolset(mockVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: testServer.URL})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)

		dataMap, ok := result.Data.(map[string]any)
		require.True(t, ok)
		body := dataMap["body"].(string)
		assert.Equal(t, 1024*1024, len(body))
	})

	t.Run("response exceeds size limit", func(t *testing.T) {
		// Create 10MB response (exceeds 5MB limit)
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", 10*1024*1024))
			w.WriteHeader(http.StatusOK)
			// Write 10MB of data
			chunk := make([]byte, 1024*1024) // 1MB chunks
			for i := 0; i < 10; i++ {
				_, _ = w.Write(chunk)
			}
		}))
		defer testServer.Close()

		mockVal := &mockHTTPValidator{
			allowedTestURLs: map[string]bool{testServer.URL: true},
			client:          &http.Client{},
		}

		nt, err := NewNetworkToolset(mockVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: testServer.URL})
		require.NoError(t, err)
		assert.Equal(t, StatusError, result.Status)
		assert.Equal(t, ErrCodeIO, result.Error.Code)
		assert.Contains(t, result.Error.Message, "exceeds limit")
	})
}

// TestNetworkToolset_HTTPGet_Redirects tests redirect handling
func TestNetworkToolset_HTTPGet_Redirects(t *testing.T) {
	t.Parallel()

	toolCtx := &ai.ToolContext{Context: context.Background()}

	t.Run("single redirect - success", func(t *testing.T) {
		// Create target server
		targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Final destination"))
		}))
		defer targetServer.Close()

		// Create redirect server
		redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, targetServer.URL, http.StatusFound)
		}))
		defer redirectServer.Close()

		mockVal := &mockHTTPValidator{
			allowedTestURLs: map[string]bool{
				redirectServer.URL: true,
				targetServer.URL:   true,
			},
			client: &http.Client{},
		}

		nt, err := NewNetworkToolset(mockVal, testLogger())
		require.NoError(t, err)

		result, err := nt.HTTPGet(toolCtx, HTTPGetInput{URL: redirectServer.URL})
		require.NoError(t, err)
		assert.Equal(t, StatusSuccess, result.Status)

		dataMap, ok := result.Data.(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "Final destination", dataMap["body"])
	})
}

// TestNetworkToolset_ToolMetadata tests tool metadata
func TestNetworkToolset_ToolMetadata(t *testing.T) {
	t.Parallel()

	httpVal := security.NewHTTP()
	nt, err := NewNetworkToolset(httpVal, testLogger())
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
	require.Len(t, tools, 1)

	tool := tools[0]
	assert.Equal(t, "httpGet", tool.Name())
	assert.NotEmpty(t, tool.Description())
	assert.Contains(t, tool.Description(), "HTTP GET")
	assert.Contains(t, tool.Description(), "SSRF")
	assert.True(t, tool.IsLongRunning())
}
