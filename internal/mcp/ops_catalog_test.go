package mcp

import (
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Koopa0/koopa/internal/mcp/ops"
)

// TestOpsCatalogDrift enforces parity between the static ops.All() catalog
// and the actual tool registrations in NewServer. Adding a tool without a
// catalog entry, or declaring a catalog entry without a registration, must
// fail this test.
//
// The test constructs a Server without stores (nil DB interfaces) and
// invokes NewServer to trigger the real registration path. Tool handlers
// are never called, so nil stores are safe.
func TestOpsCatalogDrift(t *testing.T) {
	s := NewServer(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	registered := slices.Clone(s.registeredNames)
	catalog := make([]string, 0, len(ops.All()))
	for _, m := range ops.All() {
		catalog = append(catalog, m.Name)
	}

	if diff := cmp.Diff(catalog, registered); diff != "" {
		t.Errorf("ops.All() vs registered tools mismatch (-catalog +registered):\n%s", diff)
	}

	seen := make(map[string]struct{}, len(registered))
	for _, name := range registered {
		if _, dup := seen[name]; dup {
			t.Errorf("tool %q registered twice", name)
		}
		seen[name] = struct{}{}
	}
}

// TestOpsCatalogMetaFields asserts every catalog entry carries the fields
// required for admin metadata rendering. A missing domain or description
// would leak into the /api/admin/ops response as empty strings.
func TestOpsCatalogMetaFields(t *testing.T) {
	for _, m := range ops.All() {
		t.Run(m.Name, func(t *testing.T) {
			if m.Name == "" {
				t.Error("Name is empty")
			}
			if m.Domain == "" {
				t.Error("Domain is empty")
			}
			if m.Writability == "" {
				t.Error("Writability is empty")
			}
			if m.Stability == "" {
				t.Error("Stability is empty")
			}
			if m.Since == "" {
				t.Error("Since is empty")
			}
			if m.Description == "" {
				t.Error("Description is empty")
			}
		})
	}
}
