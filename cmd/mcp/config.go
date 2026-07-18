// Copyright 2026 Koopa. All rights reserved.

// config.go owns the env→struct translation for the MCP server.
//
// This file is the only place in the MCP binary permitted to call
// os.Getenv (see .claude/rules/go-philosophy.md). It also owns the
// default CallerAgent selection: it defaults to empty. There is no
// "unknown" fallback — a tool call without an explicit `as` field, and
// without a KOOPA_MCP_CALLER_AGENT override, has no caller identity and
// is refused at withActorTx, so no write is ever attributed to a
// fabricated or anonymous actor. Declaring `as` is mandatory for every
// write; it is attribution only, not a privilege level (Option B: no
// tool-layer authorization).
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
}

func loadConfig(logger *slog.Logger) config {
	cfg := config{
		Transport: envOr("MCP_TRANSPORT", "http"),
		Port:      envOr("MCP_PORT", "8081"),
	}

	cfg.DatabaseURL = requireEnv("DATABASE_URL", logger)

	// Default caller agent: empty — there is no 'unknown' fallback. Each
	// project's instructions tell the AI to pass as: "<agent_name>" in every
	// tool call; a write call that omits it is refused at withActorTx (empty
	// caller identity). There is no tool-layer authz (Option B) — access is
	// bounded by the MCP transport (HTTP Bearer + admin-email OAuth, or the
	// stdio process boundary). For a single-agent deployment (e.g. stdio where
	// every call is one known agent) pin KOOPA_MCP_CALLER_AGENT to that name.
	cfg.CallerAgent = envOr("KOOPA_MCP_CALLER_AGENT", "")

	// HTTP transport requires MCP_TOKEN + Google OAuth
	cfg.MCPToken = os.Getenv("MCP_TOKEN")
	cfg.MCPBaseURL = envOr("MCP_BASE_URL", "https://mcp.koopa0.dev")
	cfg.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	cfg.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	cfg.AdminEmail = os.Getenv("ADMIN_EMAIL")

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
