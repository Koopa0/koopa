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
// Optional integrations (Google OAuth, R2 upload) are gated by emptiness
// of their respective fields in main; required fields are loaded via
// requireEnv and never empty by the time main observes them.
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

	// R2 upload
	R2Endpoint        string
	R2AccessKeyID     string
	R2SecretAccessKey string
	R2Bucket          string
	R2PublicURL       string

	// Site URL for RSS/sitemap
	SiteURL string
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
		R2Endpoint:         os.Getenv("R2_ENDPOINT"),
		R2AccessKeyID:      os.Getenv("R2_ACCESS_KEY_ID"),
		R2SecretAccessKey:  os.Getenv("R2_SECRET_ACCESS_KEY"),
		R2Bucket:           os.Getenv("R2_BUCKET"),
		R2PublicURL:        os.Getenv("R2_PUBLIC_URL"),
		SiteURL:            envOr("SITE_URL", "https://koopa0.dev"),
	}
	return cfg
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
