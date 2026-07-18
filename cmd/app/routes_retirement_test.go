// Copyright 2026 Koopa. All rights reserved.

package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Koopa0/koopa/internal/content"
)

func TestPublicSearchRouteIsRetired(t *testing.T) {
	mux := http.NewServeMux()
	passThrough := func(next http.Handler) http.Handler { return next }
	registerRoutes(mux, &handlers{
		content:        content.NewHandler(nil, "https://example.com", slog.Default()),
		logger:         slog.Default(),
		metricsHandler: http.NotFoundHandler(),
	}, passThrough, passThrough)

	search := httptest.NewRecorder()
	mux.ServeHTTP(search, httptest.NewRequest(http.MethodGet, "/api/search", http.NoBody))
	if search.Code != http.StatusNotFound {
		t.Fatalf("GET /api/search status = %d, want %d", search.Code, http.StatusNotFound)
	}

	health := httptest.NewRecorder()
	mux.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if health.Code != http.StatusOK {
		t.Fatalf("positive control GET /healthz status = %d, want %d", health.Code, http.StatusOK)
	}
}
