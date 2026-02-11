package tools

import (
	"testing"
	"time"
)

// BenchmarkClampTopK benchmarks the clampTopK function.
func BenchmarkClampTopK(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = clampTopK(5, 3)
	}
}

// BenchmarkResultConstruction benchmarks Result struct creation.
func BenchmarkResultConstruction(b *testing.B) {
	b.Run("success", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = Result{
				Status: StatusSuccess,
				Data:   map[string]any{"key": "value"},
			}
		}
	})

	b.Run("error", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = Result{
				Status: StatusError,
				Error:  &Error{Code: ErrCodeSecurity, Message: "test error"},
			}
		}
	})
}

// BenchmarkNetworkCreation benchmarks Network constructor.
func BenchmarkNetworkCreation(b *testing.B) {
	cfg := NetConfig{
		SearchBaseURL:    "http://localhost:8080",
		FetchParallelism: 2,
		FetchDelay:       time.Second,
		FetchTimeout:     30 * time.Second,
	}
	logger := testLogger()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = NewNetwork(cfg, logger)
	}
}

// BenchmarkFilterURLs benchmarks URL filtering and validation.
func BenchmarkFilterURLs(b *testing.B) {
	cfg := NetConfig{
		SearchBaseURL:    "http://localhost:8080",
		FetchParallelism: 2,
		FetchDelay:       time.Second,
		FetchTimeout:     30 * time.Second,
	}
	nt, _ := NewNetwork(cfg, testLogger())

	urls := []string{
		"https://example.com/",
		"https://google.com/",
		"https://github.com/",
		"http://localhost/",   // should be blocked
		"http://192.168.1.1/", // should be blocked
		"https://example.org/",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = nt.filterURLs(urls)
	}
}

// BenchmarkExtractNonHTMLContent benchmarks non-HTML content extraction.
func BenchmarkExtractNonHTMLContent(b *testing.B) {
	b.Run("json", func(b *testing.B) {
		body := []byte(`{"key": "value", "nested": {"a": 1, "b": 2}}`)
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_, _ = extractNonHTMLContent(body, "application/json")
		}
	})

	b.Run("text", func(b *testing.B) {
		body := []byte("Plain text content here")
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_, _ = extractNonHTMLContent(body, "text/plain")
		}
	})

	b.Run("large_json", func(b *testing.B) {
		// Create a larger JSON payload
		body := make([]byte, 10000)
		copy(body, `{"data": "`)
		for i := 10; i < 9990; i++ {
			body[i] = 'x'
		}
		copy(body[9990:], `"}`)

		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_, _ = extractNonHTMLContent(body, "application/json")
		}
	})
}

// BenchmarkFetchState benchmarks concurrent state operations.
func BenchmarkFetchState(b *testing.B) {
	b.Run("addResult", func(b *testing.B) {
		state := &fetchState{
			processedURL: make(map[string]struct{}),
		}
		result := FetchResult{
			URL:         "https://example.com/",
			Title:       "Example",
			Content:     "Content here",
			ContentType: "text/html",
		}

		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			state.addResult(result)
		}
	})

	b.Run("markProcessed", func(b *testing.B) {
		state := &fetchState{
			processedURL: make(map[string]struct{}),
		}

		b.ReportAllocs()
		b.ResetTimer()
		i := 0
		for b.Loop() {
			state.markProcessed("https://example.com/page" + string(rune(i%100)))
			i++
		}
	})
}

// BenchmarkKnowledgeSearchInput benchmarks the unified search input struct.
func BenchmarkKnowledgeSearchInput(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = KnowledgeSearchInput{
			Query: "test query",
			TopK:  5,
		}
	}
}
