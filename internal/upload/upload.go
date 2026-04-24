// Package upload handles file uploads to Cloudflare R2.
//
// Surface is one endpoint (POST /api/admin/upload). Safety rails:
//
//   - 5 MB max via http.MaxBytesReader + ParseMultipartForm.
//   - MIME allowlist (jpeg/png/webp/gif) resolved by
//     http.DetectContentType on the first 512 bytes, NOT the client
//     Content-Type header — a client claiming image/png on an
//     executable payload is rejected at detection time.
//   - Storage keys are `uploads/<uuidv4><ext>`, no user-controlled
//     path segments — neutralises traversal even though S3 doesn't
//     resolve paths filesystem-style.
//
// File map:
//   - upload.go (this file) — constants + response shape.
//   - client.go             — S3 client constructor (one object created
//     at startup, reused per request).
//   - handler.go            — the HTTP handler.
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
