// Package api provides shared HTTP response helpers for all handlers.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
)

// Response wraps data with optional pagination metadata.
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
// Defaults: page=1, perPage=20. Maximum perPage is 100.
func ParsePagination(r *http.Request) (page, perPage int) {
	page = 1
	perPage = 20
	if v := r.URL.Query().Get("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := r.URL.Query().Get("per_page"); v != "" {
		if pp, err := strconv.Atoi(v); err == nil && pp > 0 && pp <= 100 {
			perPage = pp
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
