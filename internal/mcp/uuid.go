package mcp

import (
	"fmt"

	"github.com/google/uuid"
)

// parseOptionalUUID parses a nullable string pointer as a UUID and returns
// (nil, nil) for absent or empty input. On a malformed UUID it returns an
// error naming the field without wrapping uuid.Parse's underlying message,
// so clients see "invalid <field>" instead of uuid-package internals
// ("invalid UUID length: 3", "invalid UUID format", etc.) at the MCP
// boundary.
//
// Consolidated from the former parseNamedUUID (hypothesis.go) and the
// unnamed parseOptionalUUID (plan.go). The single signature is
// (raw *string, fieldName string) — all MCP callers already know the
// field name at the call site, and echoing it in errors is the only thing
// the two helpers ever differed on.
func parseOptionalUUID(raw *string, fieldName string) (*uuid.UUID, error) {
	if raw == nil || *raw == "" {
		return nil, nil
	}
	parsed, err := uuid.Parse(*raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s", fieldName)
	}
	return &parsed, nil
}
