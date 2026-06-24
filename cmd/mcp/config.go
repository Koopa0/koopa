// Copyright 2026 Koopa. All rights reserved.

// config.go owns the env→struct translation for the MCP server.
//
// This file is the only place in the MCP binary permitted to call
// os.Getenv (see .claude/rules/go-philosophy.md). It also owns the
// default CallerAgent selection: unless overridden by the env var,
// every incoming tool call without an explicit `as` field is
// attributed to "unknown" — a zero-privilege agent registered in
// agent.BuiltinAgents(). The earlier default of "human" silently
// granted full human authority to any caller that forgot to set `as`,
// which is the fail-open trap this default closes.
package main

import (
	"log/slog"
	"os"
)

// config holds every value the MCP binary reads from the environment.
// Fields populated via requireEnv are guaranteed non-empty after
// loadConfig; optional integrations gate on emptiness at use time.
type config struct {
	DatabaseURL        string
	Transport          string
	Port               string
	CallerAgent        string
	MCPToken           string
	MCPBaseURL         string
	AdminEmail         string
	GoogleClientID     string
	GoogleClientSecret string
	GeminiAPIKey       string
}

func loadConfig(logger *slog.Logger) config {
	cfg := config{
		Transport: envOr("MCP_TRANSPORT", "http"),
		Port:      envOr("MCP_PORT", "8081"),
	}

	cfg.DatabaseURL = requireEnv("DATABASE_URL", logger)

	// Default caller agent: "unknown" — fail-closed. Each Cowork project's
	// instructions tell the AI to pass as: "planner" (or its real agent name)
	// in every tool call. A client that forgets is attributed to "unknown",
	// which project_progress / review_period do NOT count as owner activity
	// (there is no tool-layer authz to refuse it — Option B). Override only
	// when the deployment genuinely has a single legitimate default (e.g. a
	// personal-use deploy where all calls are from Koopa) — pin to "human"
	// explicitly in that case rather than relying on the implicit default.
	cfg.CallerAgent = envOr("KOOPA_MCP_CALLER_AGENT", "unknown")

	// HTTP transport requires MCP_TOKEN + Google OAuth
	cfg.MCPToken = os.Getenv("MCP_TOKEN")
	cfg.MCPBaseURL = envOr("MCP_BASE_URL", "https://mcp.koopa0.dev")
	cfg.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	cfg.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	cfg.AdminEmail = os.Getenv("ADMIN_EMAIL")

	// Optional: enables the semantic branch of search_knowledge. Absent
	// key falls back to FTS-only retrieval — server still starts.
	cfg.GeminiAPIKey = os.Getenv("GEMINI_API_KEY")

	return cfg
}

func requireEnv(key string, logger *slog.Logger) string {
	v := os.Getenv(key)
	if v == "" {
		logger.Error(key + " is required")
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
