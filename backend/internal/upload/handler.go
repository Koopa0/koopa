package upload

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/api"
)

// Handler handles file upload HTTP requests.
type Handler struct {
	client    *s3.Client
	bucket    string
	publicURL string // e.g. "https://pub-xxx.r2.dev"
	logger    *slog.Logger
}

// NewHandler returns an upload Handler.
func NewHandler(client *s3.Client, bucket, publicURL string, logger *slog.Logger) *Handler {
	return &Handler{
		client:    client,
		bucket:    bucket,
		publicURL: strings.TrimRight(publicURL, "/"),
		logger:    logger,
	}
}

// Upload handles POST /api/admin/upload.
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFileSize+1024) // extra room for multipart headers

	if err := r.ParseMultipartForm(maxFileSize); err != nil {
		api.Error(w, http.StatusBadRequest, "file_too_large", "file exceeds 5MB limit")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		api.Error(w, http.StatusBadRequest, "missing_file", "file field is required")
		return
	}
	defer file.Close() //nolint:errcheck // best-effort close on upload file

	// detect content type from file header bytes
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "read_error", "unable to read file")
		return
	}
	contentType := http.DetectContentType(buf[:n])

	ext, ok := allowedTypes[contentType]
	if !ok {
		api.Error(w, http.StatusBadRequest, "unsupported_type",
			fmt.Sprintf("file type %s is not supported; allowed: jpeg, png, webp, gif", contentType))
		return
	}

	// reset reader to beginning
	if _, err := file.Seek(0, 0); err != nil {
		api.Error(w, http.StatusInternalServerError, "seek_error", "unable to process file")
		return
	}

	key := "uploads/" + uuid.New().String() + ext

	_, err = h.client.PutObject(r.Context(), &s3.PutObjectInput{
		Bucket:             aws.String(h.bucket),
		Key:                aws.String(key),
		Body:               file,
		ContentType:        aws.String(contentType),
		ContentDisposition: aws.String("inline"),
	})
	if err != nil {
		h.logger.Error("uploading to r2", "key", key, "error", err)
		api.Error(w, http.StatusInternalServerError, "upload_failed", "failed to upload file")
		return
	}

	url := h.publicURL + "/" + key

	h.logger.Info("file uploaded", "key", key, "size", header.Size, "type", contentType)

	api.Encode(w, http.StatusOK, api.Response{Data: Result{URL: url}})
}
