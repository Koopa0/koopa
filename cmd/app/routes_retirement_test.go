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

func TestKnowledgeGraphRouteIsRetired(t *testing.T) {
	mux := http.NewServeMux()
	passThrough := func(next http.Handler) http.Handler { return next }
	registerRoutes(mux, &handlers{
		content:        content.NewHandler(nil, "https://example.com", slog.Default()),
		logger:         slog.Default(),
		metricsHandler: http.NotFoundHandler(),
	}, passThrough, passThrough)

	req := httptest.NewRequest(http.MethodGet, "/api/knowledge-graph", http.NoBody)
	if _, pattern := mux.Handler(req); pattern != "" {
		t.Fatalf("GET /api/knowledge-graph still matches route %q", pattern)
	}

	graph := httptest.NewRecorder()
	mux.ServeHTTP(graph, req)
	if graph.Code != http.StatusNotFound {
		t.Fatalf("GET /api/knowledge-graph status = %d, want %d", graph.Code, http.StatusNotFound)
	}
}

func TestContentWithdrawalRoutesReplaceVisibilityBypass(t *testing.T) {
	mux := http.NewServeMux()
	authCalls := 0
	adminCalls := 0
	authOnly := func(_ http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			authCalls++
			w.WriteHeader(http.StatusAccepted)
		})
	}
	adminOnly := func(_ http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			adminCalls++
			w.WriteHeader(http.StatusNoContent)
		})
	}
	registerRoutes(mux, &handlers{
		content:        content.NewHandler(nil, "https://example.com", slog.Default()),
		logger:         slog.Default(),
		metricsHandler: http.NotFoundHandler(),
	}, authOnly, adminOnly)

	const id = "11111111-1111-4111-8111-111111111111"
	tests := []struct {
		name        string
		method      string
		path        string
		wantPattern string
	}{
		{
			name:        "withdraw is a dedicated transition",
			method:      http.MethodPost,
			path:        "/api/admin/knowledge/content/" + id + "/withdraw",
			wantPattern: "POST /api/admin/knowledge/content/{id}/withdraw",
		},
		{
			name:        "restore is a dedicated transition",
			method:      http.MethodPost,
			path:        "/api/admin/knowledge/content/" + id + "/restore",
			wantPattern: "POST /api/admin/knowledge/content/{id}/restore",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, http.NoBody)
			if _, pattern := mux.Handler(req); pattern != tt.wantPattern {
				t.Fatalf("%s %s matched %q, want %q", tt.method, tt.path, pattern, tt.wantPattern)
			}
			beforeAdmin := adminCalls
			beforeAuth := authCalls
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent || adminCalls != beforeAdmin+1 || authCalls != beforeAuth {
				t.Fatalf("%s %s did not traverse admin middleware: status=%d admin=%d->%d auth=%d->%d",
					tt.method, tt.path, w.Code, beforeAdmin, adminCalls, beforeAuth, authCalls)
			}
		})
	}

	legacyPath := "/api/admin/knowledge/content/" + id + "/is-public"
	legacyReq := httptest.NewRequest(http.MethodPatch, legacyPath,
		strings.NewReader(`{"is_public":false}`))
	if _, pattern := mux.Handler(legacyReq); pattern != "" {
		t.Fatalf("PATCH %s still matches retired route %q", legacyPath, pattern)
	}
	legacy := httptest.NewRecorder()
	mux.ServeHTTP(legacy, legacyReq)
	if legacy.Code != http.StatusNotFound {
		t.Fatalf("PATCH %s status = %d, want %d", legacyPath, legacy.Code, http.StatusNotFound)
	}
}
