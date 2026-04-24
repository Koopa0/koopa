// Package api provides shared HTTP response helpers for all handlers.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
)

// Response wraps data with optional pagination metadata.
// Data is `any` because handlers return different domain types. Using generics
// (Response[T]) was evaluated but would require every handler to specify the type
// parameter, adding verbosity with no runtime safety gain (JSON encoding is untyped).
type Response struct {
	Data any   `json:"data"`
	Meta *Meta `json:"meta,omitempty"`
}

// Meta contains pagination metadata.
type Meta struct {
	Total      int `json:"total"`
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
}

// ErrorBody is the standard error response.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail contains error code and message.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Encode writes a JSON response with the given status code.
func Encode[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encoding response", "error", err)
	}
}

// maxRequestBody is the default request body size limit (1 MB).
const maxRequestBody = 1 << 20

// Decode reads a JSON request body into T, enforcing a 1 MB size limit.
// Uses http.MaxBytesReader which returns a clear error when the limit is exceeded.
func Decode[T any](w http.ResponseWriter, r *http.Request) (T, error) {
	var v T
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	err := json.NewDecoder(r.Body).Decode(&v)
	return v, err
}

// Error writes a standard error response.
func Error(w http.ResponseWriter, status int, code, message string) {
	Encode(w, status, ErrorBody{
		Error: ErrorDetail{Code: code, Message: message},
	})
}

// ParsePagination extracts page and per_page query parameters.
// Defaults: page=1, perPage=20. Out-of-range values are clamped:
// page < 1 → 1, per_page < 1 → 1, per_page > 100 → 100.
// Non-numeric values fall back to defaults.
func ParsePagination(r *http.Request) (page, perPage int) {
	page = 1
	perPage = 20
	if v := r.URL.Query().Get("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			page = max(p, 1)
		}
	}
	if v := r.URL.Query().Get("per_page"); v != "" {
		if pp, err := strconv.Atoi(v); err == nil {
			perPage = min(max(pp, 1), 100)
		}
	}
	return page, perPage
}

// PagedResponse builds a Response with pagination meta.
func PagedResponse(data any, total, page, perPage int) Response {
	totalPages := total / perPage
	if total%perPage != 0 {
		totalPages++
	}
	return Response{
		Data: data,
		Meta: &Meta{
			Total:      total,
			Page:       page,
			PerPage:    perPage,
			TotalPages: totalPages,
		},
	}
}

// ErrMap maps a sentinel error to an HTTP status and error code.
//
// Message is the client-facing string written into the response body. It
// MUST NOT leak Go-internal package prefixes (e.g. "hypothesis: …") or
// implementation details and is REQUIRED — HandleError panics on an entry
// with an empty Message. The panic is intentional: a missing Message is
// a programmer bug (every sentinel needs a deliberate client-facing
// string), not a runtime condition the caller can handle. The recovery
// middleware in cmd/app catches it and returns a 500, and the missing
// Message surfaces loudly in logs instead of silently leaking the
// sentinel's internal Error() text to clients. See the enum switch
// default pattern in .claude/rules/error-handling.md.
type ErrMap struct {
	Target  error
	Status  int
	Code    string
	Message string
}

// HandleError writes an error response by checking sentinel error mappings.
// The first matching sentinel wins. Unknown errors are logged and return 500.
// Each matching ErrMap MUST declare a non-empty Message (see ErrMap doc);
// HandleError panics otherwise.
func HandleError(w http.ResponseWriter, logger *slog.Logger, err error, maps ...ErrMap) {
	for _, m := range maps {
		if errors.Is(err, m.Target) {
			if m.Message == "" {
				// Programmer bug: every ErrMap MUST specify a client-facing
				// Message. Fail loudly at request time instead of leaking
				// the sentinel's internal Error() text. Recovery middleware
				// returns a 500 to the client.
				panic("api.ErrMap: Message is required — target=" + m.Target.Error())
			}
			Error(w, m.Status, m.Code, m.Message)
			return
		}
	}
	logger.Error("internal error", "error", err)
	Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
}
