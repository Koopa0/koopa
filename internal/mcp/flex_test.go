package mcp

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/jsonschema-go/jsonschema"
	segjson "github.com/segmentio/encoding/json"
)

func TestFlexIntUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    FlexInt
		wantErr bool
	}{
		{name: "integer", input: `7`, want: 7},
		{name: "zero", input: `0`, want: 0},
		{name: "negative", input: `-5`, want: -5},
		{name: "string integer", input: `"7"`, want: 7},
		{name: "string zero", input: `"0"`, want: 0},
		{name: "string negative", input: `"-5"`, want: -5},
		{name: "string float", input: `"7.5"`, wantErr: true},
		{name: "string non-numeric", input: `"abc"`, wantErr: true},
		{name: "string empty", input: `""`, wantErr: true},
		{name: "boolean", input: `true`, wantErr: true},
		{name: "null", input: `null`, want: 0},
		{name: "array", input: `[1]`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got FlexInt
			err := got.UnmarshalJSON([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got FlexInt(%d)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFlexIntSegmentioUnmarshal(t *testing.T) {
	type input struct {
		Days FlexInt `json:"days,omitempty"`
	}

	tests := []struct {
		name    string
		json    string
		want    input
		wantErr bool
	}{
		{name: "integer", json: `{"days":7}`, want: input{Days: 7}},
		{name: "string", json: `{"days":"7"}`, want: input{Days: 7}},
		{name: "omitted", json: `{}`, want: input{Days: 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := segjson.NewDecoder(bytes.NewReader([]byte(tt.json)))
			var got input
			err := dec.Decode(&got)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestRawMessageSchemaIsObject is the regression guard for a schema-drift
// bug found in the learning audit round: json.RawMessage fields on tool
// inputs were generating a byte-array schema ({"type":"array","items":
// {"type":"integer","minimum":0,"maximum":255}}) because jsonschema-go
// introspects the underlying []byte. Callers hand-encoding a JSON object
// as an integer list is obviously not what record_attempt.metadata
// wants — it wants "any JSON object".
//
// This test locks in the override: a RawMessage-typed input field must
// accept a JSON object and reject a byte list.
func TestRawMessageSchemaIsObject(t *testing.T) {
	type input struct {
		Metadata json.RawMessage `json:"metadata,omitempty"`
	}

	schema, err := jsonschema.ForType(reflect.TypeFor[input](), &jsonschema.ForOptions{
		TypeSchemas: flexTypeSchemas,
	})
	if err != nil {
		t.Fatalf("generating schema: %v", err)
	}

	// Direct shape check: the generated schema for metadata must declare
	// type=object, NOT type=array. A future change that removes the
	// RawMessage override would flip this back to array and a caller
	// paste-debugging would be a nightmare.
	metaSchema, ok := schema.Properties["metadata"]
	if !ok {
		t.Fatal("metadata property missing from generated schema")
	}
	if metaSchema.Type != "object" {
		t.Errorf("metadata schema type = %q, want %q (byte-array regression)", metaSchema.Type, "object")
	}

	// Marshal the schema to JSON — this is the exact path the MCP SDK
	// takes when building the tools/list response. An earlier version used
	// Extra{"additionalProperties":true} which crashed with "map key
	// additionalProperties duplicates struct field" during marshal,
	// breaking the entire tool list endpoint.
	if _, err := json.Marshal(schema); err != nil {
		t.Fatalf("schema marshal failed (MCP tool list would be broken): %v", err)
	}

	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatalf("resolving schema: %v", err)
	}

	tests := []struct {
		name    string
		value   map[string]any
		wantErr bool
	}{
		{
			name:  "object with nested fields (the 8-step checklist case)",
			value: map[string]any{"metadata": map[string]any{"complexity": map[string]any{"time": "O(n)"}, "pattern": "hash-map"}},
		},
		{
			name:  "empty object",
			value: map[string]any{"metadata": map[string]any{}},
		},
		{
			name:  "omitted",
			value: map[string]any{},
		},
		{
			name:    "integer byte list — was the broken shape before the override",
			value:   map[string]any{"metadata": []any{123, 34, 112, 97}},
			wantErr: true,
		},
		{
			name:    "plain string",
			value:   map[string]any{"metadata": "not an object"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := resolved.Validate(&tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%v) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestFlexIntSchemaValidation(t *testing.T) {
	type input struct {
		Days FlexInt `json:"days,omitempty"`
	}

	schema, err := jsonschema.ForType(reflect.TypeFor[input](), &jsonschema.ForOptions{
		TypeSchemas: flexTypeSchemas,
	})
	if err != nil {
		t.Fatalf("generating schema: %v", err)
	}

	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatalf("resolving schema: %v", err)
	}

	tests := []struct {
		name    string
		value   map[string]any
		wantErr bool
	}{
		{name: "integer", value: map[string]any{"days": float64(7)}},
		{name: "string", value: map[string]any{"days": "7"}},
		{name: "omitted", value: map[string]any{}},
		{name: "boolean", value: map[string]any{"days": true}, wantErr: true},
		{name: "array", value: map[string]any{"days": []any{1}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := resolved.Validate(&tt.value)
			if tt.wantErr && err == nil {
				t.Fatal("want error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestFlexIntOmitempty(t *testing.T) {
	type input struct {
		Days FlexInt `json:"days,omitempty"`
	}

	got, err := json.Marshal(input{Days: 0})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(`{}`, string(got)); diff != "" {
		t.Errorf("zero FlexInt should be omitted (-want +got):\n%s", diff)
	}

	got, err = json.Marshal(input{Days: 7})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(`{"days":7}`, string(got)); diff != "" {
		t.Errorf("non-zero FlexInt (-want +got):\n%s", diff)
	}
}

func TestFlexStringSliceUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    FlexStringSlice
		wantErr bool
	}{
		{name: "array", input: `["a","b"]`, want: FlexStringSlice{"a", "b"}},
		{name: "empty array", input: `[]`, want: FlexStringSlice{}},
		{name: "null", input: `null`, want: nil},
		{name: "string-encoded array", input: `"[\"a\",\"b\"]"`, want: FlexStringSlice{"a", "b"}},
		{name: "string-encoded empty", input: `"[]"`, want: FlexStringSlice{}},
		{name: "plain string", input: `"hello"`, wantErr: true},
		{name: "string-encoded int array", input: `"[1, 2]"`, wantErr: true},
		{name: "integer", input: `7`, wantErr: true},
		{name: "boolean", input: `true`, wantErr: true},
		{name: "exceeds max length", input: `["` + strings.Repeat(`","`, maxFlexStringSliceLen) + `"]`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got FlexStringSlice
			err := got.UnmarshalJSON([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFlexStringSliceSegmentioUnmarshal(t *testing.T) {
	type input struct {
		Tags FlexStringSlice `json:"tags,omitempty"`
	}

	tests := []struct {
		name    string
		json    string
		want    input
		wantErr bool
	}{
		{name: "array", json: `{"tags":["a","b"]}`, want: input{Tags: FlexStringSlice{"a", "b"}}},
		{name: "string", json: `{"tags":"[\"a\",\"b\"]"}`, want: input{Tags: FlexStringSlice{"a", "b"}}},
		{name: "omitted", json: `{}`, want: input{}},
		{name: "invalid type", json: `{"tags":7}`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := segjson.NewDecoder(bytes.NewReader([]byte(tt.json)))
			var got input
			err := dec.Decode(&got)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFlexStringSliceSchemaValidation(t *testing.T) {
	type input struct {
		Tags FlexStringSlice `json:"tags,omitempty"`
	}

	schema, err := jsonschema.ForType(reflect.TypeFor[input](), &jsonschema.ForOptions{
		TypeSchemas: flexTypeSchemas,
	})
	if err != nil {
		t.Fatalf("generating schema: %v", err)
	}

	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatalf("resolving schema: %v", err)
	}

	tests := []struct {
		name    string
		value   map[string]any
		wantErr bool
	}{
		{name: "array", value: map[string]any{"tags": []any{"a", "b"}}},
		{name: "string", value: map[string]any{"tags": `["a","b"]`}},
		{name: "null", value: map[string]any{"tags": nil}},
		{name: "omitted", value: map[string]any{}},
		{name: "integer", value: map[string]any{"tags": 7}, wantErr: true},
		{name: "boolean", value: map[string]any{"tags": true}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := resolved.Validate(&tt.value)
			if tt.wantErr && err == nil {
				t.Fatal("want error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}
