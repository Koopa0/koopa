package build

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCurrentReturnsLinkTimeIdentity(t *testing.T) {
	// Defaults apply when -ldflags wasn't passed (typical `go test ./...`
	// path). The constants here must match the package-level var defaults
	// — a divergence means someone changed one without the other and
	// stamped binaries would also drift.
	want := Info{SHA: "dev", BuiltAt: "unknown", Version: "v0.0.0-dev"}
	got := Current()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Current() mismatch (-want +got):\n%s", diff)
	}
}
