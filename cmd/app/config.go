// Copyright 2026 Koopa. All rights reserved.

// config.go owns the env→struct translation for the app server.
//
// This file is the only place in the entire app binary that may call
// os.Getenv (see .claude/rules/go-philosophy.md). Every other package
// receives configuration through explicit struct fields or constructor
// parameters, so tests don't touch the environment and dependencies are
// wired at main() rather than discovered at use time.
//
// requireEnv exits the process on missing required vars — that is the
// correct response at startup; downstream code can rely on the fields
// being populated.
package main

import (
	"log/slog"
	"os"
)

// config holds every value the app server reads from the environment.
// Optional integrations (Google OAuth) are gated by emptiness of their
// respective fields in main; required fields are loaded via requireEnv
// and never empty by the time main observes them.
type config struct {
	Port       string
	CORSOrigin string

	DatabaseURL string

	JWTSecret string

	// Google OAuth
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string
	AdminEmail         string

	// Gemini embedding. Empty = embedding reconciler disabled; search
	// stays FTS-only.
	GeminiAPIKey string

	// Site URL for RSS/sitemap
	SiteURL string

	// Observability — see cmd/app/observability.go.
	// ObservabilityEnabled is the master kill switch. When false, /metrics
	// returns 404 and the OTel MeterProvider is a no-op. Implies disabling
	// QueryTracingEnabled (all-or-nothing per design).
	ObservabilityEnabled bool
	// QueryTracingEnabled gates otelpgx wiring on the pgxpool. Adds ~2 allocs
	// per query under no-op provider; keep off in benchmarks. Requires
	// ObservabilityEnabled=true.
	QueryTracingEnabled bool
	// ServiceVersion populates the OTel resource attribute service.version.
	// Defaults to "dev"; production deploys should set KOOPA_VERSION to the
	// build SHA or release tag.
	ServiceVersion string
	// Environment populates the OTel resource attribute deployment.environment.name.
	Environment string
}

func loadConfig(logger *slog.Logger) config {
	cfg := config{
		Port:               envOr("PORT", "8080"),
		CORSOrigin:         envOr("CORS_ORIGIN", "http://localhost:4200"),
		DatabaseURL:        requireEnv("DATABASE_URL", logger),
		JWTSecret:          requireEnv("JWT_SECRET", logger),
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURI:  os.Getenv("GOOGLE_REDIRECT_URI"),
		AdminEmail:         os.Getenv("ADMIN_EMAIL"),
		GeminiAPIKey:       os.Getenv("GEMINI_API_KEY"),
		SiteURL:            envOr("SITE_URL", "https://koopa0.dev"),

		ObservabilityEnabled: envBoolOr("KOOPA_OBSERVABILITY_ENABLED", true),
		QueryTracingEnabled:  envBoolOr("KOOPA_QUERY_TRACING_ENABLED", false),
		ServiceVersion:       envOr("KOOPA_VERSION", "dev"),
		Environment:          envOr("KOOPA_ENV", "dev"),
	}
	return cfg
}

// backfillConfig holds the environment the embed-backfill one-shot needs.
// Both values are required — a backfill cannot run without a database or
// a Gemini key, so missing either exits at startup.
type backfillConfig struct {
	DatabaseURL  string
	GeminiAPIKey string
}

func loadBackfillConfig(logger *slog.Logger) backfillConfig {
	return backfillConfig{
		DatabaseURL:  requireEnv("DATABASE_URL", logger),
		GeminiAPIKey: requireEnv("GEMINI_API_KEY", logger),
	}
}

// queryTracingOn folds the all-or-nothing kill-switch semantics (Q3):
// otelpgx wiring is gated by BOTH ObservabilityEnabled and
// QueryTracingEnabled.
//
// Pointer receiver despite config's value-semantic usage elsewhere
// (loadConfig returns by value, run() holds it by value) because
// gocritic's hugeParam fires on receivers >80B and config is 264B.
// Lint preference overrides receiver-consistency convention here; this
// is the only method on config so the asymmetry is contained.
func (c *config) queryTracingOn() bool {
	return c.ObservabilityEnabled && c.QueryTracingEnabled
}

func envBoolOr(key string, fallback bool) bool {
	switch os.Getenv(key) {
	case "":
		return fallback
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return fallback
	}
}

func requireEnv(key string, logger *slog.Logger) string {
	v := os.Getenv(key)
	if v == "" {
		logger.Error("required environment variable not set", "key", key)
		os.Exit(1)
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
