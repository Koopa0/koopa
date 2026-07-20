//go:build integration

// Copyright 2026 Koopa. All rights reserved.

package main

import (
	"net/http"
	"testing"

	"github.com/Koopa0/koopa/internal/testdb"
)

func TestReadyz_RealPostgres(t *testing.T) {
	pool, cleanup := testdb.NewPool()
	t.Cleanup(cleanup)

	got := readyzStatus(t, pool)
	if got != http.StatusOK {
		t.Errorf("GET /readyz with real PostgreSQL status = %d, want %d", got, http.StatusOK)
	}
}
