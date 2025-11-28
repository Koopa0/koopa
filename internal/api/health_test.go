package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/stretchr/testify/assert"
)

func TestHealth_Liveness(t *testing.T) {
	logger := log.NewNop()
	h := NewHealth(nil, logger) // pool not needed for liveness

	req := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	w := httptest.NewRecorder()

	h.liveness(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}

func TestHealth_Readiness_PoolNil(t *testing.T) {
	logger := log.NewNop()
	h := NewHealth(nil, logger)

	req := httptest.NewRequest(http.MethodGet, "/ready", http.NoBody)
	w := httptest.NewRecorder()

	h.readiness(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "database pool not configured")
}
