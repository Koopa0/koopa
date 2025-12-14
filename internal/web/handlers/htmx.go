package handlers

import "net/http"

// HTMX header constants and helper functions.
// This file provides a consistent interface for HTMX request detection
// across all handlers, eliminating magic string literals like "true".

// htmxRequestHeader is the standard header that HTMX sends with all requests.
const htmxRequestHeader = "HX-Request"

// htmxRequestTrue is the value HTMX sends for HX-Request header.
// Defined as constant to satisfy goconst lint rule.
const htmxRequestTrue = "true"

// IsHTMX returns true if the request was made by HTMX.
// Use this instead of directly checking r.Header.Get("HX-Request") == "true".
func IsHTMX(r *http.Request) bool {
	return r.Header.Get(htmxRequestHeader) == htmxRequestTrue
}
