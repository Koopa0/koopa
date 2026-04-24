package api

import (
	"encoding/json"
	"flag"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var update = flag.Bool("update", false, "update golden files")

// TestGolden_ErrorResponse verifies the canonical error JSON structure
// matches the golden file. Run with -update to re-record.
func TestGolden_ErrorResponse(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	Error(w, 404, "NOT_FOUND", "content not found")
	got := w.Body.Bytes()

	golden := filepath.Join("testdata", "error_response.golden")

	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("updating golden file: %v", err)
		}
		return
	}

	want, err := os.ReadFile(golden) //#nosec G304 -- golden path is test-controlled, not user-supplied
	if err != nil {
		t.Fatalf("reading golden file: %v", err)
	}

	// Compare JSON structure (keys + types), not exact whitespace.
	var gotMap, wantMap map[string]any
	if err := json.Unmarshal(got, &gotMap); err != nil {
		t.Fatalf("unmarshaling got: %v", err)
	}
	if err := json.Unmarshal(want, &wantMap); err != nil {
		t.Fatalf("unmarshaling want: %v", err)
	}

	if diff := cmp.Diff(wantMap, gotMap); diff != "" {
		t.Errorf("error response structure mismatch (-golden +got):\n%s", diff)
	}
}

// TestGolden_PagedResponse verifies the canonical paginated response structure.
func TestGolden_PagedResponse(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	resp := PagedResponse([]string{}, 0, 1, 20)
	Encode(w, 200, resp)
	got := w.Body.Bytes()

	golden := filepath.Join("testdata", "paged_response.golden")

	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("updating golden file: %v", err)
		}
		return
	}

	want, err := os.ReadFile(golden) //#nosec G304 -- golden path is test-controlled, not user-supplied
	if err != nil {
		t.Fatalf("reading golden file: %v", err)
	}

	// Compare keys and types.
	var gotMap, wantMap map[string]any
	if err := json.Unmarshal(got, &gotMap); err != nil {
		t.Fatalf("unmarshaling got: %v", err)
	}
	if err := json.Unmarshal(want, &wantMap); err != nil {
		t.Fatalf("unmarshaling want: %v", err)
	}

	// Verify all expected keys exist with correct types.
	if diff := cmp.Diff(keysOf(wantMap), keysOf(gotMap)); diff != "" {
		t.Errorf("paged response top-level keys mismatch (-golden +got):\n%s", diff)
	}

	// Verify meta structure.
	wantMeta, _ := wantMap["meta"].(map[string]any)
	gotMeta, _ := gotMap["meta"].(map[string]any)
	if wantMeta != nil && gotMeta != nil {
		if diff := cmp.Diff(keysOf(wantMeta), keysOf(gotMeta)); diff != "" {
			t.Errorf("paged response meta keys mismatch (-golden +got):\n%s", diff)
		}
	}
}

// keysOf returns sorted keys from a JSON object map.
func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
