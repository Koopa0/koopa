// Copyright 2026 Koopa. All rights reserved.

package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReadyz_ClosedPool(t *testing.T) {
	pool, err := pgxpool.New(t.Context(), "postgres://test:test@localhost/test?sslmode=disable")
	if err != nil {
		t.Fatalf("pgxpool.New() error: %v", err)
	}
	pool.Close()

	got := readyzStatus(t, pool)
	if got != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz with closed pool status = %d, want %d", got, http.StatusServiceUnavailable)
	}
}

func readyzStatus(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	mux := http.NewServeMux()
	registerRoutes(
		mux,
		&handlers{
			pool:           pool,
			logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
			metricsHandler: http.NotFoundHandler(),
		},
		func(next http.Handler) http.Handler { return next },
		func(next http.Handler) http.Handler { return next },
	)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody))
	return recorder.Code
}
