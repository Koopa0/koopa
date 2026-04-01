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

// flexIntSchema is the JSON schema override for FlexInt fields.
var flexIntSchema = &jsonschema.Schema{Types: []string{"integer", "string"}}

// flexIntTypeSchemas maps FlexInt to its dual-type schema for use with
// jsonschema.ForType's TypeSchemas option.
var flexIntTypeSchemas = map[reflect.Type]*jsonschema.Schema{
	reflect.TypeFor[FlexInt](): flexIntSchema,
}
