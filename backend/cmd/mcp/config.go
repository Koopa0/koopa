package main

import (
	"log/slog"
	"os"
)

type config struct {
	DatabaseURL        string
	Transport          string
	Port               string
	MCPToken           string
	NotionAPIKey       string
	AdminAPIURL        string
	JWTSecret          string
	AdminEmail         string
	ORMJWT             string
	GeminiAPIKey       string
	GoogleClientID     string
	GoogleClientSecret string
}

func loadConfig(logger *slog.Logger) config {
	cfg := config{
		Transport: envOr("MCP_TRANSPORT", "http"),
		Port:      envOr("MCP_PORT", "8081"),
	}

	cfg.DatabaseURL = requireEnv("DATABASE_URL", logger)

	// HTTP transport requires MCP_TOKEN + Google OAuth
	cfg.MCPToken = os.Getenv("MCP_TOKEN")
	cfg.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	cfg.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	cfg.AdminEmail = os.Getenv("ADMIN_EMAIL")

	// Optional integrations
	cfg.NotionAPIKey = os.Getenv("NOTION_API_KEY")
	cfg.AdminAPIURL = os.Getenv("ADMIN_API_URL")
	cfg.JWTSecret = os.Getenv("JWT_SECRET")
	cfg.ORMJWT = os.Getenv("ORM_JWT")
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
