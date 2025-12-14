package tools

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/koopa0/koopa-cli/internal/log"
)

// NewNetworkToolsetForTesting creates a NetworkToolset with SSRF protection disabled.
//
// SECURITY WARNING: This bypasses SSRF protection and MUST ONLY be used in tests.
// It is in internal/ to prevent external package usage.
// Production code should ALWAYS use NewNetworkToolset instead.
func NewNetworkToolsetForTesting(
	searchBaseURL string,
	fetchParallelism int,
	fetchDelay time.Duration,
	fetchTimeout time.Duration,
	logger log.Logger,
) (*NetworkToolset, error) {
	if searchBaseURL == "" {
		return nil, fmt.Errorf("search base URL is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	if fetchParallelism <= 0 {
		fetchParallelism = 2
	}
	if fetchDelay <= 0 {
		fetchDelay = 1 * time.Second
	}
	if fetchTimeout <= 0 {
		fetchTimeout = 30 * time.Second
	}

	// CRITICAL: No URL validator - SSRF protection disabled for testing
	return &NetworkToolset{
		searchBaseURL:    strings.TrimSuffix(searchBaseURL, "/"),
		searchClient:     &http.Client{Timeout: 30 * time.Second},
		fetchParallelism: fetchParallelism,
		fetchDelay:       fetchDelay,
		fetchTimeout:     fetchTimeout,
		urlValidator:     nil, // SSRF protection bypassed
		skipSSRFCheck:    true,
		logger:           logger,
	}, nil
}
