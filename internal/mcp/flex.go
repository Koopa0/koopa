package mcp

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"

	"github.com/google/jsonschema-go/jsonschema"
)

// FlexInt accepts both JSON integer and string values during unmarshaling.
// This works around a known Cowork serialization bug where all MCP tool
// parameters are sent as strings (anthropics/claude-code#26027).
type FlexInt int

// UnmarshalJSON accepts a JSON number (7) or a numeric string ("7").
func (f *FlexInt) UnmarshalJSON(data []byte) error {
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		*f = FlexInt(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("invalid integer string: %q", s)
		}
		*f = FlexInt(n)
		return nil
	}
	return fmt.Errorf("cannot unmarshal %s as integer", data)
}

// FlexStringSlice accepts both JSON array and string values during unmarshaling.
// This works around the same Cowork serialization bug where array parameters
// are sent as stringified JSON (anthropics/claude-code#26027).
type FlexStringSlice []string

// maxFlexStringSliceLen caps the number of elements to prevent write amplification.
const maxFlexStringSliceLen = 500

// UnmarshalJSON accepts a JSON array (["a","b"]) or a stringified array ("[\"a\",\"b\"]").
func (f *FlexStringSlice) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		if len(arr) > maxFlexStringSliceLen {
			return fmt.Errorf("array exceeds maximum length %d", maxFlexStringSliceLen)
		}
		*f = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if len(s) > 1<<20 {
			return fmt.Errorf("string-encoded array exceeds 1 MiB")
		}
		if err := json.Unmarshal([]byte(s), &arr); err != nil {
			return fmt.Errorf("invalid string-encoded array: %q", s)
		}
		if len(arr) > maxFlexStringSliceLen {
			return fmt.Errorf("array exceeds maximum length %d", maxFlexStringSliceLen)
		}
		*f = arr
		return nil
	}
	return fmt.Errorf("cannot unmarshal %s as string array", data)
}

// flexIntSchema is the JSON schema override for FlexInt fields.
var flexIntSchema = &jsonschema.Schema{Types: []string{"integer", "string"}}

// flexStringSliceSchema is the JSON schema override for FlexStringSlice fields.
// The "string" type accepts Cowork's stringified arrays (e.g. "[\"a\"]"). A plain
// string like "hello" passes schema validation but fails UnmarshalJSON — this
// asymmetry is intentional since only Cowork sends string-encoded values.
var flexStringSliceSchema = &jsonschema.Schema{
	Types: []string{"null", "array", "string"},
	Items: &jsonschema.Schema{Types: []string{"string"}},
}

// rawMessageSchema overrides the schema for json.RawMessage fields exposed
// as tool inputs. Without the override, jsonschema-go introspects the
// underlying []byte and emits a byte array shape
// ({"type":"array","items":{"type":"integer","minimum":0,"maximum":255}}),
// which forces every caller to hand-encode their free-form JSON as an
// integer byte list. That is obviously not what record_attempt.metadata
// wants — it wants "any JSON object" so callers can pass 8-step checklist
// output like {"complexity":{"time":"O(n)"},"pattern":"hash-map"}.
//
// Using an empty object schema ({}) would technically accept any JSON
// value, but clients (Claude Desktop, Cowork) render empty schemas as
// "any" which is unhelpful UX. {"type":"object"} + explicit
// additionalProperties:true communicates "pass a JSON object, any keys"
// while keeping the shape self-documenting.
var rawMessageSchema = &jsonschema.Schema{
	Type: "object",
	Extra: map[string]any{
		"additionalProperties": true,
	},
}

// flexTypeSchemas maps flex types to their schema overrides for use with
// jsonschema.ForType's TypeSchemas option.
var flexTypeSchemas = map[reflect.Type]*jsonschema.Schema{
	reflect.TypeFor[FlexInt]():         flexIntSchema,
	reflect.TypeFor[FlexStringSlice](): flexStringSliceSchema,
	reflect.TypeFor[json.RawMessage](): rawMessageSchema,
}
