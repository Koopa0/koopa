// Copyright 2026 Koopa. All rights reserved.

package main

import (
	"reflect"
	"testing"
)

// TestConfigHasNoGeminiCapability locks the owner decision that the MCP server
// does not perform embedding or knowledge retrieval. Reintroducing a provider
// credential here would silently recreate that retired runtime dependency.
func TestConfigHasNoGeminiCapability(t *testing.T) {
	typeOfConfig := reflect.TypeFor[config]()
	if field, ok := typeOfConfig.FieldByName("GeminiAPIKey"); ok {
		t.Fatalf("retired Gemini capability remains in MCP config as field %s", field.Name)
	}
}
