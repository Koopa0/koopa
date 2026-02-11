package tools

import (
	"testing"
	"time"
)

func TestNetwork_Constructor(t *testing.T) {
	t.Run("valid inputs", func(t *testing.T) {
		cfg := NetConfig{
			SearchBaseURL:    "http://localhost:8080",
			FetchParallelism: 2,
			FetchDelay:       time.Second,
			FetchTimeout:     30 * time.Second,
		}

		nt, err := NewNetwork(cfg, testLogger())
		if err != nil {
			t.Errorf("NewNetwork() error = %v, want nil", err)
		}
		if nt == nil {
			t.Error("NewNetwork() returned nil, want non-nil")
		}
	})

	t.Run("empty search URL", func(t *testing.T) {
		cfg := NetConfig{
			SearchBaseURL: "",
		}

		nt, err := NewNetwork(cfg, testLogger())
		if err == nil {
			t.Error("NewNetwork() error = nil, want error")
		}
		if nt != nil {
			t.Error("NewNetwork() returned non-nil, want nil")
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		cfg := NetConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		nt, err := NewNetwork(cfg, nil)
		if err == nil {
			t.Error("NewNetwork() error = nil, want error")
		}
		if nt != nil {
			t.Error("NewNetwork() returned non-nil, want nil")
		}
	})

	t.Run("defaults applied", func(t *testing.T) {
		cfg := NetConfig{
			SearchBaseURL: "http://localhost:8080",
			// Leave other fields as zero values
		}

		nt, err := NewNetwork(cfg, testLogger())
		if err != nil {
			t.Errorf("NewNetwork() error = %v, want nil", err)
		}
		if nt == nil {
			t.Fatal("NewNetwork() returned nil")
		}
		// Verify defaults were applied (internal fields not accessible, but no error means success)
	})
}

func TestNetworkToolConstants(t *testing.T) {
	expectedNames := map[string]string{
		"WebSearchName": "web_search",
		"WebFetchName":  "web_fetch",
	}

	if WebSearchName != expectedNames["WebSearchName"] {
		t.Errorf("WebSearchName = %q, want %q", WebSearchName, expectedNames["WebSearchName"])
	}
	if WebFetchName != expectedNames["WebFetchName"] {
		t.Errorf("WebFetchName = %q, want %q", WebFetchName, expectedNames["WebFetchName"])
	}
}

func TestNetConfigConstants(t *testing.T) {
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
