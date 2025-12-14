//go:build dev

// Package static provides filesystem-based static assets for development.
package static

import "net/http"

// Handler returns an http.Handler that serves static assets from the filesystem.
// In development mode, this allows hot-reloading of CSS changes.
func Handler() http.Handler {
	return http.FileServer(http.Dir("./internal/web/static"))
}
