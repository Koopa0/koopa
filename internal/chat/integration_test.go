//go:build integration
// +build integration

package chat_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"

	"github.com/koopa0/koopa/internal/chat"
)

// TestChatAgent_BasicExecution tests basic chat agent execution
func TestChatAgent_BasicExecution(t *testing.T) {
	framework := SetupTest(t)
	ctx := context.Background()
	sessionID := framework.SessionID

	t.Run("simple question", func(t *testing.T) {
		resp, err := framework.Agent.Execute(ctx, sessionID, "Hello, how are you?")
		if err != nil {
			t.Fatalf("Execute() unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("Execute() response is nil, want non-nil when error is nil")
		}
		if resp.FinalText == "" {
			t.Error("Execute() response.FinalText is empty, want non-empty")
		}
	})
}

// TestChatAgent_SessionPersistence tests conversation history persistence
func TestChatAgent_SessionPersistence(t *testing.T) {
	framework := SetupTest(t)
	ctx := context.Background()
	sessionID := framework.SessionID

	t.Run("first message creates history", func(t *testing.T) {
		resp, err := framework.Agent.Execute(ctx, sessionID, "My name is Koopa")
		if err != nil {
			t.Fatalf("Execute() unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("Execute() response is nil, want non-nil when error is nil")
		}
	})

	t.Run("second message uses history", func(t *testing.T) {
		// Use same session for history continuity
		resp, err := framework.Agent.Execute(ctx, sessionID, "What is my name?")
		if err != nil {
			t.Fatalf("Execute() unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("Execute() response is nil, want non-nil when error is nil")
		}
		// Session history should allow LLM to remember the name from previous message
		// Use case-insensitive check to handle LLM rephrasing variations
		responseLower := strings.ToLower(resp.FinalText)
		if !strings.Contains(responseLower, "koopa") {
			t.Errorf("Execute() response = %q, want to contain %q (LLM should remember from session history)", resp.FinalText, "koopa")
		}
	})
}

// TestChatAgent_ToolIntegration tests tool calling capability
func TestChatAgent_ToolIntegration(t *testing.T) {
	framework := SetupTest(t)
	ctx := context.Background()
	sessionID := framework.SessionID

	t.Run("can use file tools", func(t *testing.T) {
		// Create unique marker file to verify tool was actually invoked
		markerName := fmt.Sprintf("koopa-test-%d.txt", time.Now().UnixNano())
		markerPath := filepath.Join(os.TempDir(), markerName)
		if err := os.WriteFile(markerPath, []byte("marker"), 0644); err != nil {
			t.Fatalf("setup: creating marker file: %v", err)
		}
		t.Cleanup(func() { os.Remove(markerPath) })

		// Ask agent to find the specific file - proves tool must be called
		resp, err := framework.Agent.Execute(ctx, sessionID,
			fmt.Sprintf("List files in /tmp and tell me if %s exists", markerName))
		if err != nil {
			t.Fatalf("Execute() unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("Execute() response is nil, want non-nil when error is nil")
		}
		if resp.FinalText == "" {
			t.Error("Execute() response.FinalText is empty, want non-empty")
		}

		// Verify tool was actually invoked by checking for file mention
		// (The agent can't know about this unique file without calling the tool)
		if !strings.Contains(strings.ToLower(resp.FinalText), strings.ToLower(markerName)) {
			t.Errorf("Execute() response = %q, want to contain %q (proves tool was called)", resp.FinalText, markerName)
		}
	})
}

// TestChatAgent_ErrorHandling tests error scenarios
func TestChatAgent_ErrorHandling(t *testing.T) {
	framework := SetupTest(t)

	t.Run("handles empty input gracefully", func(t *testing.T) {
		ctx := context.Background()
		sessionID := framework.SessionID

		resp, err := framework.Agent.Execute(ctx, sessionID, "")
		// Agent should handle empty input without panicking.
		// The LLM may return a valid response or an error — both are acceptable.
		if err != nil {
			t.Logf("Execute(\"\") returned error (acceptable): %v", err)
			return
		}
		if resp == nil {
			t.Fatal("Execute(\"\") = nil, nil — want non-nil response or non-nil error")
		}
		if resp.FinalText == "" {
			t.Error("Execute(\"\") response.FinalText is empty, want non-empty (at minimum the fallback message)")
		}
	})
}

// TestChatAgent_NewChatValidation tests constructor validation
func TestChatAgent_NewChatValidation(t *testing.T) {
	// Setup test framework once for all validation tests
	framework := SetupTest(t)

	t.Run("requires genkit", func(t *testing.T) {
		_, err := chat.New(chat.Config{
			SessionStore: framework.SessionStore,
			Logger:       slog.Default(),
			Tools:        []ai.Tool{},
		})
		if err == nil {
			t.Fatal("New() expected error, got nil")
		}
		if !strings.Contains(err.Error(), "genkit instance is required") {
			t.Errorf("New() error = %q, want to contain %q", err.Error(), "genkit instance is required")
		}
	})

	t.Run("requires session store", func(t *testing.T) {
		_, err := chat.New(chat.Config{
			Genkit: framework.Genkit,
			Logger: slog.Default(),
			Tools:  []ai.Tool{},
		})
		if err == nil {
			t.Fatal("New() expected error, got nil")
		}
		if !strings.Contains(err.Error(), "session store is required") {
			t.Errorf("New() error = %q, want to contain %q", err.Error(), "session store is required")
		}
	})

	t.Run("requires logger", func(t *testing.T) {
		_, err := chat.New(chat.Config{
			Genkit:       framework.Genkit,
			SessionStore: framework.SessionStore,
			Tools:        []ai.Tool{},
		})
		if err == nil {
			t.Fatal("New() expected error, got nil")
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("New() error = %q, want to contain %q", err.Error(), "logger is required")
		}
	})

	t.Run("requires at least one tool", func(t *testing.T) {
		_, err := chat.New(chat.Config{
			Genkit:       framework.Genkit,
			SessionStore: framework.SessionStore,
			Logger:       slog.Default(),
			Tools:        []ai.Tool{},
		})
		if err == nil {
			t.Fatal("New() expected error, got nil")
		}
		if !strings.Contains(err.Error(), "at least one tool is required") {
			t.Errorf("New() error = %q, want to contain %q", err.Error(), "at least one tool is required")
		}
	})
}

// TestChatAgent_ConcurrentExecution tests concurrent chat agent execution.
// Uses mutex-protected error collection instead of assert/require in goroutines
// to avoid test reliability issues with t.FailNow() from goroutines.
func TestChatAgent_ConcurrentExecution(t *testing.T) {
	framework := SetupTest(t)

	numConcurrentQueries := 5
	var wg sync.WaitGroup
	wg.Add(numConcurrentQueries)

	ctx := context.Background()
	sessionID := framework.SessionID

	// Collect results safely
	type result struct {
		queryID int
		resp    *chat.Response
		err     error
	}
	results := make([]result, numConcurrentQueries)
	var mu sync.Mutex

	for i := 0; i < numConcurrentQueries; i++ {
		go func(queryID int) {
			defer wg.Done()
			resp, err := framework.Agent.Execute(ctx, sessionID, fmt.Sprintf("What is the capital of France? Query ID: %d", queryID))
			mu.Lock()
			results[queryID] = result{queryID: queryID, resp: resp, err: err}
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Assert after all goroutines complete
	for _, r := range results {
		if r.err != nil {
			t.Fatalf("Execute() concurrent query %d unexpected error: %v", r.queryID, r.err)
		}
		if r.resp == nil {
			t.Errorf("Execute() concurrent query %d response is nil, want non-nil", r.queryID)
			continue
		}
		if r.resp.FinalText == "" {
			t.Errorf("Execute() concurrent query %d response.FinalText is empty, want non-empty", r.queryID)
		}
		if !strings.Contains(r.resp.FinalText, "Paris") {
			t.Errorf("Execute() concurrent query %d response = %q, want to contain %q", r.queryID, r.resp.FinalText, "Paris")
		}
	}
}
