// Copyright 2026 Koopa. All rights reserved.

package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestAdminSearchRouteIsRetired(t *testing.T) {
	mux := http.NewServeMux()
	passThrough := func(next http.Handler) http.Handler { return next }
	registerRoutes(mux, &handlers{
		content:        content.NewHandler(nil, "https://example.com", slog.Default()),
		logger:         slog.Default(),
		metricsHandler: http.NotFoundHandler(),
	}, passThrough, passThrough)

	search := httptest.NewRecorder()
	mux.ServeHTTP(search, httptest.NewRequest(http.MethodGet, "/api/admin/search", http.NoBody))
	if search.Code != http.StatusNotFound {
		t.Fatalf("GET /api/admin/search status = %d, want %d", search.Code, http.StatusNotFound)
	}
}

func TestRelatedContentRouteIsRetired(t *testing.T) {
	mux := http.NewServeMux()
	passThrough := func(next http.Handler) http.Handler { return next }
	registerRoutes(mux, &handlers{
		content:        content.NewHandler(nil, "https://example.com", slog.Default()),
		logger:         slog.Default(),
		metricsHandler: http.NotFoundHandler(),
	}, passThrough, passThrough)

	related := httptest.NewRecorder()
	path := "/api/contents/related/" + strings.Repeat("a", 201)
	mux.ServeHTTP(related, httptest.NewRequest(http.MethodGet, path, http.NoBody))
	if related.Code != http.StatusNotFound {
		t.Fatalf("GET %s status = %d, want %d", path, related.Code, http.StatusNotFound)
	}
}
