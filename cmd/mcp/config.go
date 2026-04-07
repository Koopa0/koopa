package main

import (
	"log/slog"
	"os"
)

type config struct {
	DatabaseURL        string
	Transport          string
	Port               string
	Participant        string
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

	// Default participant: "human" (safest default).
	// Each Cowork project's instructions tell the AI to pass as: "hq"
	// in tool calls. The server trusts the caller's self-identification
	// and validates via capability flags, not transport identity.
	cfg.Participant = envOr("KOOPA_MCP_PARTICIPANT", "human")

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
