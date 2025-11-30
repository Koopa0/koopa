package component_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/koopa0/koopa-cli/internal/ui/web/component"
)

func TestButton_Variants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		props    component.ButtonProps
		contains []string
	}{
		{
			name:  "primary button (default)",
			props: component.ButtonProps{},
			contains: []string{
				"bg-primary-600",
				"text-white",
				"focus-visible:ring",
				"type=\"button\"",
			},
		},
		{
			name:  "secondary button",
			props: component.ButtonProps{Variant: "secondary"},
			contains: []string{
				"border",
				"border-gray-300",
			},
		},
		{
			name:  "ghost button",
			props: component.ButtonProps{Variant: "ghost"},
			contains: []string{
				"text-gray-600",
				"hover:bg-gray-100",
			},
		},
		{
			name:  "danger button",
			props: component.ButtonProps{Variant: "danger"},
			contains: []string{
				"bg-error-600",
				"hover:bg-error-700",
			},
		},
		{
			name:  "disabled button",
			props: component.ButtonProps{Disabled: true},
			contains: []string{
				"opacity-50",
				"cursor-not-allowed",
				"disabled",
			},
		},
		{
			name:  "loading button",
			props: component.ButtonProps{Loading: true},
			contains: []string{
				"cursor-wait",
				"opacity-90",
				"animate-spin", // spinner
			},
		},
		{
			name:  "submit button",
			props: component.ButtonProps{Type: component.ButtonTypeSubmit},
			contains: []string{
				"type=\"submit\"",
			},
		},
		{
			name:  "small button",
			props: component.ButtonProps{Size: "sm"},
			contains: []string{
				"px-3",
				"text-sm",
			},
		},
		{
			name:  "large button",
			props: component.ButtonProps{Size: "lg"},
			contains: []string{
				"px-6",
				"text-lg",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			err := component.Button(tt.props).Render(context.Background(), &buf)
			if err != nil {
				t.Fatalf("render failed: %v", err)
			}

			html := buf.String()
			for _, want := range tt.contains {
				if !strings.Contains(html, want) {
					t.Errorf("missing %q in output:\n%s", want, html)
				}
			}
		})
	}
}

func TestButton_MinTouchTarget(t *testing.T) {
	t.Parallel()

	// All sizes should have minimum 44px touch target
	sizes := []string{"sm", "md", "lg", ""}

	for _, size := range sizes {
		t.Run("size_"+size, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			props := component.ButtonProps{Size: size}
			err := component.Button(props).Render(context.Background(), &buf)
			if err != nil {
				t.Fatalf("render failed: %v", err)
			}

			html := buf.String()
			if !strings.Contains(html, "min-h-[44px]") && !strings.Contains(html, "min-h-[48px]") {
				t.Errorf("missing minimum touch target for size %q", size)
			}
		})
	}
}
