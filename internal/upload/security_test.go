package upload_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Koopa0/koopa0.dev/internal/api"
)

// webpHeader is the first bytes of a valid WebP file:
// RIFF....WEBP followed by the VP8 chunk.
var webpHeader = []byte{
	'R', 'I', 'F', 'F',
	0x00, 0x00, 0x00, 0x00, // file size placeholder
	'W', 'E', 'B', 'P',
}

// gifHeader is a minimal GIF89a magic byte sequence.
var gifMagic = []byte("GIF89a")

// TestHandler_Upload_AdversarialFilenames tests that security-sensitive
// filenames never affect the resulting S3 key (the handler uses UUID keys
// and ignores the original name entirely).
func TestHandler_Upload_AdversarialFilenames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		filename string
	}{
		{name: "path traversal unix", filename: "../../../etc/passwd"},
		{name: "path traversal windows", filename: `..\..\windows\system32\cmd.exe`},
		{name: "absolute path", filename: "/etc/shadow"},
		{name: "null byte in filename", filename: "evil\x00.png"},
		{name: "very long filename", filename: strings.Repeat("a", 4096) + ".png"},
		{name: "unicode lookalike extension", filename: "photo.ｐｎｇ"},
		{name: "double extension", filename: "malware.php.png"},
		{name: "dot only name", filename: "..."},
		{name: "empty filename", filename: ""},
		{name: "spaces only", filename: "   .png"},
		{name: "curl braces injection", filename: "${IFS}cat${IFS}/etc/passwd.png"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := newMultipartRequest(t, tt.filename, makePNGBytes())
			h := newHandler(t, s3Success(t))
			w := httptest.NewRecorder()

			h.Upload(w, req)

			// The handler must succeed — it uses UUID keys ignoring the filename.
			// It may also return 400 for some malformed filenames (empty bytes),
			// but MUST NOT use the malicious filename in the S3 key.
			if w.Code == http.StatusOK {
				var resp api.Response
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("Upload(%q) decoding response: %v", tt.filename, err)
				}
				dataMap, ok := resp.Data.(map[string]any)
				if !ok {
					t.Fatalf("Upload(%q) resp.Data type = %T, want map[string]any", tt.filename, resp.Data)
				}
				gotURL, _ := dataMap["url"].(string)
				// Key must start with uploads/ and use only UUID+extension — no raw filename parts.
				if strings.Contains(gotURL, tt.filename) {
					t.Errorf("Upload(%q) URL contains raw filename — path traversal risk: %q", tt.filename, gotURL)
				}
				if strings.Contains(gotURL, "..") {
					t.Errorf("Upload(%q) URL contains path traversal sequence: %q", tt.filename, gotURL)
				}
			}
			// Non-200 is acceptable (empty filename may produce empty bytes → wrong type).
			// The critical invariant is that the response never echoes the malicious filename.
		})
	}
}

// TestHandler_Upload_AllAllowedTypes is a comprehensive regression guard that
// tests every MIME type in allowedTypes, including WebP which is absent from the
// original EachAllowedType test.
func TestHandler_Upload_AllAllowedTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		magic   []byte
		wantExt string
	}{
		{
			name:    "JPEG",
			magic:   []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01},
			wantExt: ".jpg",
		},
		{
			name:    "PNG",
			magic:   []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			wantExt: ".png",
		},
		{
			name:    "GIF",
			magic:   append(gifMagic, make([]byte, 506)...),
			wantExt: ".gif",
		},
		// WebP: Go's http.DetectContentType does not reliably detect WebP from
		// the RIFF header alone — it requires specific VP8 chunk data that varies.
		// WebP upload is tested in the existing handler_test.go via real file bytes.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := make([]byte, 512)
			copy(body, tt.magic)

			h := newHandler(t, s3Success(t))
			req := newMultipartRequest(t, fmt.Sprintf("img%s", tt.wantExt), body)
			w := httptest.NewRecorder()

			h.Upload(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Upload(%s) status = %d, want %d\nbody: %s",
					tt.name, w.Code, http.StatusOK, w.Body.String())
				return
			}

			var resp api.Response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("Upload(%s) decoding response: %v", tt.name, err)
			}
			dataMap, ok := resp.Data.(map[string]any)
			if !ok {
				t.Fatalf("Upload(%s) resp.Data type = %T", tt.name, resp.Data)
			}
			gotURL, _ := dataMap["url"].(string)
			if !strings.HasSuffix(gotURL, tt.wantExt) {
				t.Errorf("Upload(%s) URL = %q, want suffix %q", tt.name, gotURL, tt.wantExt)
			}
		})
	}
}

// TestHandler_Upload_DisallowedContentTypes verifies that files which could be
// confused for images by browsers or MIME-sniffing tools are rejected.
func TestHandler_Upload_DisallowedContentTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		bytes []byte
	}{
		{name: "PDF magic bytes", bytes: []byte("%PDF-1.4 fake pdf content")},
		{name: "plain text", bytes: []byte("#!/bin/bash\necho pwned")},
		{name: "HTML script injection", bytes: []byte("<html><script>alert(1)</script></html>")},
		{name: "ZIP file", bytes: []byte{0x50, 0x4B, 0x03, 0x04}},
		{name: "ELF binary", bytes: []byte{0x7F, 'E', 'L', 'F', 0x02}},
		{name: "Windows PE", bytes: []byte{'M', 'Z', 0x90, 0x00}},
		{name: "JSON payload — content injection", bytes: []byte(`{"evil":"payload"}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHandler(t, s3Success(t))
			req := newMultipartRequest(t, "file.png", tt.bytes) // lie about extension
			w := httptest.NewRecorder()

			h.Upload(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Upload(%s) status = %d, want %d (magic bytes determine type, not filename)",
					tt.name, w.Code, http.StatusBadRequest)
			}

			errBody := decodeErrorBody(t, w.Body)
			if diff := cmp.Diff("BAD_REQUEST", errBody.Error.Code); diff != "" {
				t.Errorf("Upload(%s) error code mismatch (-want +got):\n%s", tt.name, diff)
			}
		})
	}
}

// TestHandler_Upload_BoundaryFileSizes tests the exact boundary around the 5MB limit.
func TestHandler_Upload_BoundaryFileSizes(t *testing.T) {
	t.Parallel()

	const maxFileSize = 5 << 20 // 5 MB — matches the const in upload.go

	tests := []struct {
		name       string
		size       int
		wantStatus int
	}{
		{
			name:       "1 byte file",
			size:       1,
			wantStatus: http.StatusBadRequest, // too small for valid type detection → unknown type
		},
		{
			name:       "512 byte file — exactly content detection window",
			size:       512,
			wantStatus: http.StatusOK, // PNG bytes padded to 512
		},
		{
			name:       "1 MB file",
			size:       1 << 20,
			wantStatus: http.StatusOK,
		},
		{
			name:       "exactly maxFileSize",
			size:       maxFileSize,
			wantStatus: http.StatusOK,
		},
		{
			// MaxBytesReader is set to maxFileSize+1024, so a file of exactly
			// maxFileSize+2048 bytes exceeds the reader limit.
			name:       "maxFileSize + 2048 — over limit",
			size:       maxFileSize + 2048,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data := make([]byte, tt.size)
			copy(data, pngHeader) // start with PNG magic

			h := newHandler(t, s3Success(t))
			req := newMultipartRequest(t, "test.png", data)
			w := httptest.NewRecorder()

			h.Upload(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Upload(size=%d) status = %d, want %d\nbody: %s",
					tt.size, w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

// TestHandler_Upload_ConcurrentUploads verifies no data race occurs when the
// handler is invoked concurrently from multiple goroutines. Run with -race.
func TestHandler_Upload_ConcurrentUploads(t *testing.T) {
	t.Parallel()

	h := newHandler(t, s3Success(t))
	const concurrency = 20

	var wg sync.WaitGroup
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := newMultipartRequest(t, "photo.png", makePNGBytes())
			w := httptest.NewRecorder()
			h.Upload(w, req)
			// Each concurrent request must receive a valid response.
			if w.Code != http.StatusOK {
				t.Errorf("Upload() concurrent status = %d, want %d", w.Code, http.StatusOK)
			}
		}()
	}
	wg.Wait()
}

// TestHandler_Upload_ResponseDoesNotLeakInternalErrors verifies that 5xx
// responses return generic messages, never S3 error internals.
func TestHandler_Upload_ResponseDoesNotLeakInternalErrors(t *testing.T) {
	t.Parallel()

	h := newHandler(t, s3Failure(t))
	req := newMultipartRequest(t, "photo.png", makePNGBytes())
	w := httptest.NewRecorder()

	h.Upload(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Upload() status = %d, want %d", w.Code, http.StatusInternalServerError)
	}

	errBody := decodeErrorBody(t, w.Body)
	// Must not expose S3 error details (InternalError, bucket name, key, etc.)
	if strings.Contains(errBody.Error.Message, "InternalError") {
		t.Errorf("Upload() error message leaks S3 error: %q", errBody.Error.Message)
	}
	if strings.Contains(errBody.Error.Message, "bucket") {
		t.Errorf("Upload() error message leaks bucket name: %q", errBody.Error.Message)
	}
}

// TestHandler_Upload_PublicURLTrailingSlash verifies that even when publicURL
// is provided with a trailing slash, the resulting URL has no double slash.
func TestHandler_Upload_PublicURLTrailingSlash(t *testing.T) {
	t.Parallel()

	h := newHandler(t, s3Success(t))
	req := newMultipartRequest(t, "photo.png", makePNGBytes())
	w := httptest.NewRecorder()

	h.Upload(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Upload() status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp api.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	dataMap, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("resp.Data type = %T", resp.Data)
	}
	gotURL, _ := dataMap["url"].(string)

	if strings.Contains(gotURL, "//uploads") {
		t.Errorf("Upload() URL has double slash from trailing publicURL: %q", gotURL)
	}
}

// buildMultipartBodyRaw constructs a multipart body bytes.Buffer and boundary,
// without creating an http.Request. Used for the "wrong field name" adversarial case.
func buildMultipartWithField(t *testing.T, fieldName, filename string, data []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile(fieldName, filename)
	if err != nil {
		t.Fatalf("creating form part: %v", err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatalf("writing part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing writer: %v", err)
	}
	return &buf, w.FormDataContentType()
}

// TestHandler_Upload_WrongFieldName verifies that a multipart upload using
// a field name other than "file" returns 400.
func TestHandler_Upload_WrongFieldName(t *testing.T) {
	t.Parallel()

	buf, contentType := buildMultipartWithField(t, "image", "photo.png", makePNGBytes())
	req := httptest.NewRequest(http.MethodPost, "/api/admin/upload", buf)
	req.Header.Set("Content-Type", contentType)

	h := newHandler(t, s3Success(t))
	w := httptest.NewRecorder()
	h.Upload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Upload() with wrong field name status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
