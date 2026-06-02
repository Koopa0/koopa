// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"encoding/json"
	"testing"
)

// marshalToKeyMap serializes v with encoding/json and re-parses the result
// into a map keyed by top-level field name. It is the foundation of the
// aggregate output-shape tests — assertions check key presence/absence
// and per-field cardinality on the returned map.
//
// Using json.RawMessage as the value type preserves the original
// serialized form so callers can re-unmarshal specific fields (e.g. as
// []json.RawMessage to count array elements) without paying for a
// second full Marshal round.
func marshalToKeyMap(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error = %v, want nil", v, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal(%T) error = %v, want nil\nraw: %s", v, err, b)
	}
	return m
}
