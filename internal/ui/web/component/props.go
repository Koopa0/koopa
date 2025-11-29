package component

// orDefault returns val if non-empty, otherwise returns def.
func orDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}
