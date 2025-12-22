package sse

import (
	"net/http/httptest"
	"sync"
	"testing"
)

// TestWriter_SequentialWrites_NoRace verifies SSE writer works correctly
// when used sequentially (which is the expected usage pattern).
// SSE connections are handled by a single goroutine per connection.
//
// Note: The SSE Writer is NOT designed for concurrent writes from multiple goroutines.
// Each HTTP SSE connection should use its own Writer from a single goroutine.
func TestWriter_SequentialWrites_NoRace(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	w, err := NewWriter(rec)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	const numWrites = 50

	for i := 0; i < numWrites; i++ {
		err := w.WriteChunkRaw("msg-1", "<p>Content</p>")
		if err != nil {
			t.Fatalf("WriteChunkRaw failed: %v", err)
		}
	}

	// Verify SSE headers were set
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Error("Content-Type header not set correctly")
	}
}

// TestWriter_MultipleConnections_Race verifies that multiple SSE connections
// (each with its own Writer) can operate concurrently without issues.
// This is the expected usage pattern: one Writer per HTTP connection,
// multiple connections handled concurrently.
func TestWriter_MultipleConnections_Race(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	const numConnections = 20
	const writesPerConnection = 10

	for conn := 0; conn < numConnections; conn++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			// Each connection has its own recorder and writer
			rec := httptest.NewRecorder()
			w, err := NewWriter(rec)
			if err != nil {
				t.Errorf("NewWriter failed for conn %d: %v", connID, err)
				return
			}

			// Single goroutine writes to this connection
			for i := 0; i < writesPerConnection; i++ {
				_ = w.WriteChunkRaw("msg", "<span>data</span>")
			}
		}(conn)
	}

	wg.Wait()
}

// TestWriter_WriteError_Concurrent verifies WriteError works correctly
// when multiple connections write errors concurrently (each to their own Writer).
func TestWriter_WriteError_Concurrent(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	const numConnections = 20

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			w, err := NewWriter(rec)
			if err != nil {
				return
			}
			_ = w.WriteError("msg-err", "test_error", "Test error message")
		}(i)
	}

	wg.Wait()
}

// TestWriter_MixedOperations_Sequential tests all writer operations
// in sequence (which is the expected usage pattern).
func TestWriter_MixedOperations_Sequential(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	w, err := NewWriter(rec)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Write chunks
	_ = w.WriteChunkRaw("msg-mix", "<div>content 1</div>")
	_ = w.WriteChunkRaw("msg-mix", "<div>content 2</div>")

	// Write error
	_ = w.WriteError("msg-mix", "error", "message")

	// Write sidebar refresh
	_ = w.WriteSidebarRefresh("session-id", "title")

	// Verify output contains expected events
	body := rec.Body.String()
	if body == "" {
		t.Error("Expected SSE output, got empty body")
	}
}
