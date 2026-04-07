package main

import (
	"log/slog"
	"os"
)

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
