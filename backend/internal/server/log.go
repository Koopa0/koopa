package server

import (
	"context"
	"log/slog"
	"strings"
)

// sensitiveKeys lists attribute keys whose values must be redacted in logs.
var sensitiveKeys = map[string]bool{
	"password":      true,
	"token":         true,
	"authorization": true,
	"cookie":        true,
	"api_key":       true,
	"secret":        true,
	"access_token":  true,
	"refresh_token": true,
}

// SanitizingHandler wraps a slog.Handler to redact sensitive attribute values.
type SanitizingHandler struct {
	inner slog.Handler
}

// NewSanitizingHandler returns a handler that replaces sensitive fields with [REDACTED].
func NewSanitizingHandler(inner slog.Handler) *SanitizingHandler {
	return &SanitizingHandler{inner: inner}
}

func (h *SanitizingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *SanitizingHandler) Handle(ctx context.Context, r slog.Record) error {
	sanitized := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		sanitized.AddAttrs(sanitizeAttr(a))
		return true
	})
	return h.inner.Handle(ctx, sanitized)
}

func (h *SanitizingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	sanitized := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		sanitized[i] = sanitizeAttr(a)
	}
	return &SanitizingHandler{inner: h.inner.WithAttrs(sanitized)}
}

func (h *SanitizingHandler) WithGroup(name string) slog.Handler {
	return &SanitizingHandler{inner: h.inner.WithGroup(name)}
}

func sanitizeAttr(a slog.Attr) slog.Attr {
	if sensitiveKeys[strings.ToLower(a.Key)] {
		return slog.String(a.Key, "[REDACTED]")
	}
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		sanitized := make([]slog.Attr, len(attrs))
		for i, ga := range attrs {
			sanitized[i] = sanitizeAttr(ga)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(sanitized...)}
	}
	return a
}
