package upload_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/go-cmp/cmp"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/upload"
)

// fakeHTTPClient is a minimal http.Client stand-in that satisfies s3.HTTPClient.
// It returns the response produced by fn for every request.
type fakeHTTPClient struct {
	fn func(req *http.Request) (*http.Response, error)
}

func (f *fakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return f.fn(req)
}

// s3Success returns a fake S3 client whose PutObject call succeeds.
func s3Success(t *testing.T) *s3.Client {
	t.Helper()
	fake := &fakeHTTPClient{
		fn: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     http.Header{},
			}, nil
		},
	}
	return s3.New(s3.Options{
		BaseEndpoint: strPtr("https://fake.r2.example.com"),
		Region:       "auto",
		HTTPClient:   fake,
		Credentials:  noopCredentials{},
	})
}

// s3Failure returns a fake S3 client whose PutObject call returns an error response.
func s3Failure(t *testing.T) *s3.Client {
	t.Helper()
	fake := &fakeHTTPClient{
		fn: func(req *http.Request) (*http.Response, error) {
			body := `<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>We encountered an internal error</Message></Error>`
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     http.Header{"Content-Type": []string{"application/xml"}},
			}, nil
		},
	}
	return s3.New(s3.Options{
		BaseEndpoint: strPtr("https://fake.r2.example.com"),
		Region:       "auto",
		HTTPClient:   fake,
		Credentials:  noopCredentials{},
	})
}

// noopCredentials satisfies aws.CredentialsProvider without real credentials.
type noopCredentials struct{}

func (noopCredentials) Retrieve(_ context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake"}, nil
}

// newMultipartRequest builds an HTTP request with a multipart file field named "file".
// contentType is the declared Content-Type of the file bytes (not the multipart
// boundary). Pass an empty contentType to skip the part's Content-Type header
// so http.DetectContentType runs on the bytes.
func newMultipartRequest(t *testing.T, filename string, body []byte) *http.Request {
	t.Helper()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	if _, err := part.Write(body); err != nil {
		t.Fatalf("writing file bytes: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

// pngHeader is the first 8 bytes of a valid PNG file (magic bytes).
var pngHeader = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

// jpegHeader is a minimal valid JPEG SOI marker.
var jpegHeader = []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}

// makePNGBytes returns a minimal PNG-like byte slice (magic bytes + 512 bytes padding).
func makePNGBytes() []byte {
	data := make([]byte, len(pngHeader)+512)
	copy(data, pngHeader)
	return data
}

func strPtr(s string) *string { return &s }

// decodeErrorBody decodes the api.ErrorBody from the response.
func decodeErrorBody(t *testing.T, body io.Reader) api.ErrorBody {
	t.Helper()
	var errBody api.ErrorBody
	if err := json.NewDecoder(body).Decode(&errBody); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	return errBody
}

// newHandler creates an upload.Handler wired to the given S3 client.
func newHandler(t *testing.T, client *s3.Client) *upload.Handler {
	t.Helper()
	return upload.NewHandler(client, "test-bucket", "https://cdn.example.com", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestHandler_Upload(t *testing.T) {
	tests := []struct {
		name       string
		buildReq   func(t *testing.T) *http.Request
		s3Client   func(t *testing.T) *s3.Client
		wantStatus int
		wantCode   string // non-empty means check error code
		wantURLPfx string // non-empty means check response URL prefix
	}{
		{
			name: "valid PNG upload returns URL",
			buildReq: func(t *testing.T) *http.Request {
				return newMultipartRequest(t, "photo.png", makePNGBytes())
			},
			s3Client:   s3Success,
			wantStatus: http.StatusOK,
			wantURLPfx: "https://cdn.example.com/uploads/",
		},
		{
			name: "valid JPEG upload returns URL",
			buildReq: func(t *testing.T) *http.Request {
				body := make([]byte, len(jpegHeader)+256)
				copy(body, jpegHeader)
				return newMultipartRequest(t, "image.jpg", body)
			},
			s3Client:   s3Success,
			wantStatus: http.StatusOK,
			wantURLPfx: "https://cdn.example.com/uploads/",
		},
		{
			name: "missing file field returns 400",
			buildReq: func(t *testing.T) *http.Request {
				var buf bytes.Buffer
				w := multipart.NewWriter(&buf)
				_ = w.WriteField("other_field", "value")
				_ = w.Close()
				req := httptest.NewRequest(http.MethodPost, "/api/admin/upload", &buf)
				req.Header.Set("Content-Type", w.FormDataContentType())
				return req
			},
			s3Client:   s3Success,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name: "non-multipart request returns 400",
			buildReq: func(t *testing.T) *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/api/admin/upload",
					strings.NewReader(`{"file": "data"}`))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			s3Client:   s3Success,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name: "unsupported content type returns 400",
			buildReq: func(t *testing.T) *http.Request {
				// PDF magic bytes: %PDF
				pdfBytes := []byte("%PDF-1.4 fake pdf content for content type detection")
				return newMultipartRequest(t, "doc.pdf", pdfBytes)
			},
			s3Client:   s3Success,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name: "plain text file returns 400",
			buildReq: func(t *testing.T) *http.Request {
				return newMultipartRequest(t, "script.sh", []byte("#!/bin/bash\necho hello"))
			},
			s3Client:   s3Success,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name: "file exceeding 5MB limit returns 400",
			buildReq: func(t *testing.T) *http.Request {
				// Build a body clearly over maxFileSize + multipart overhead.
				// MaxBytesReader is set to maxFileSize+1024, so we need >5MB+1KB of content.
				const overLimit = (5 << 20) + 2048
				bigData := make([]byte, overLimit)
				copy(bigData, pngHeader) // start with PNG magic so type check would pass
				return newMultipartRequest(t, "huge.png", bigData)
			},
			s3Client:   s3Success,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
		{
			name: "S3 upload failure returns 500",
			buildReq: func(t *testing.T) *http.Request {
				return newMultipartRequest(t, "photo.png", makePNGBytes())
			},
			s3Client:   s3Failure,
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL",
		},
		{
			name: "path traversal in filename is ignored — key uses UUID",
			buildReq: func(t *testing.T) *http.Request {
				// The handler generates a UUID key and ignores the original filename,
				// so path traversal in the filename cannot affect the S3 key.
				return newMultipartRequest(t, "../../../etc/passwd.png", makePNGBytes())
			},
			s3Client:   s3Success,
			wantStatus: http.StatusOK,
			wantURLPfx: "https://cdn.example.com/uploads/",
		},
		{
			name: "empty file (zero bytes) returns 400",
			buildReq: func(t *testing.T) *http.Request {
				return newMultipartRequest(t, "empty.png", []byte{})
			},
			s3Client:   s3Success,
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHandler(t, tt.s3Client(t))
			req := tt.buildReq(t)
			w := httptest.NewRecorder()

			h.Upload(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Upload() status = %d, want %d\nbody: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantCode != "" {
				errBody := decodeErrorBody(t, w.Body)
				if diff := cmp.Diff(tt.wantCode, errBody.Error.Code); diff != "" {
					t.Errorf("Upload() error code mismatch (-want +got):\n%s", diff)
				}
			}

			if tt.wantURLPfx != "" {
				assertUploadURLPrefix(t, w, tt.wantURLPfx)
			}
		})
	}
}

// assertUploadURLPrefix checks that the response contains a URL with the expected prefix and a valid suffix.
func assertUploadURLPrefix(t *testing.T, w *httptest.ResponseRecorder, wantPrefix string) {
	t.Helper()
	var resp api.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding success response: %v", err)
	}
	dataMap, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("Upload() resp.Data type = %T, want map[string]any", resp.Data)
	}
	gotURL, _ := dataMap["url"].(string)
	if !strings.HasPrefix(gotURL, wantPrefix) {
		t.Errorf("Upload() URL = %q, want prefix %q", gotURL, wantPrefix)
	}
	suffix := strings.TrimPrefix(gotURL, wantPrefix)
	if len(suffix) < 5 { // minimum: "x.png"
		t.Errorf("Upload() URL suffix = %q, want UUID.ext", suffix)
	}
}

// TestHandler_Upload_ContentTypeHeader verifies the response always carries
// Content-Type: application/json.
func TestHandler_Upload_ContentTypeHeader(t *testing.T) {
	t.Parallel()

	h := newHandler(t, s3Success(t))
	req := newMultipartRequest(t, "photo.png", makePNGBytes())
	w := httptest.NewRecorder()

	h.Upload(w, req)

	got := w.Header().Get("Content-Type")
	if !strings.HasPrefix(got, "application/json") {
		t.Errorf("Upload() Content-Type = %q, want application/json", got)
	}
}

// TestHandler_Upload_URLStructure verifies uploaded file URLs follow the
// pattern: <publicURL>/uploads/<uuid><ext>.
func TestHandler_Upload_URLStructure(t *testing.T) {
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
		t.Fatalf("resp.Data type = %T, want map[string]any", resp.Data)
	}
	url, _ := dataMap["url"].(string)

	// Must be: https://cdn.example.com/uploads/<uuid>.png
	// UUID is 36 chars; with extension ".png" = 40 chars after "uploads/".
	suffix := strings.TrimPrefix(url, "https://cdn.example.com/uploads/")
	if len(suffix) < 36 {
		t.Errorf("Upload() URL key too short: %q (want UUID + extension)", suffix)
	}

	if !strings.HasSuffix(suffix, ".png") {
		t.Errorf("Upload() URL = %q, want .png extension for PNG upload", url)
	}

	// Verify the key does not contain path traversal sequences.
	if strings.Contains(suffix, "..") || strings.Contains(suffix, "/") {
		t.Errorf("Upload() URL key contains suspicious path: %q", suffix)
	}
}

// TestHandler_Upload_EachAllowedType confirms every supported MIME type
// produces a 200 response (regression guard for the allowedTypes map).
func TestHandler_Upload_EachAllowedType(t *testing.T) {
	// Magic byte sequences for each allowed image type.
	type imageFixture struct {
		name    string
		magic   []byte
		wantExt string
	}
	fixtures := []imageFixture{
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
			magic:   []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\xFF\xFF\xFF\x00\x00\x00!\xF9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"),
			wantExt: ".gif",
		},
	}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()

			body := make([]byte, 512)
			copy(body, fx.magic)

			h := newHandler(t, s3Success(t))
			req := newMultipartRequest(t, fmt.Sprintf("img%s", fx.wantExt), body)
			w := httptest.NewRecorder()

			h.Upload(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Upload(%s) status = %d, want %d\nbody: %s", fx.name, w.Code, http.StatusOK, w.Body.String())
			}
		})
	}
}
