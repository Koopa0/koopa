// Package upload handles file uploads to Cloudflare R2.
package upload

// maxFileSize is the maximum upload size (5 MB).
const maxFileSize = 5 << 20

// allowedTypes maps MIME types to file extensions.
var allowedTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/webp": ".webp",
	"image/gif":  ".gif",
}

// Result is the upload response payload.
type Result struct {
	URL string `json:"url"`
}
