//go:build !dev

// Package static provides embedded static assets for production builds.
package static

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
)

//go:embed css/*.css css/prism/*.css js/*.js js/prism/*.js
var assetsFS embed.FS

// Handler returns an http.Handler that serves embedded static assets.
// Panics if the embedded filesystem is corrupted, which should never happen
// at runtime since assets are embedded at compile time.
func Handler() http.Handler {
	sub, err := fs.Sub(assetsFS, ".")
	if err != nil {
		// This should never happen with embed.FS and "." path,
		// but fail fast at initialization if assets are corrupted.
		panic(fmt.Sprintf("static: failed to create sub-filesystem: %v", err))
	}
	return http.FileServer(http.FS(sub))
}
