package page

import (
	"bytes"
	"context"
	"testing"
)

// BenchmarkGeneralSettings_Render benchmarks General settings form rendering.
func BenchmarkGeneralSettings_Render(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := GeneralSettings("test-token").Render(context.Background(), &buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSecuritySettings_Render benchmarks Security settings form rendering.
func BenchmarkSecuritySettings_Render(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := SecuritySettings("test-token").Render(context.Background(), &buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAppearanceSettings_Render benchmarks Appearance settings form rendering.
func BenchmarkAppearanceSettings_Render(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := AppearanceSettings("test-token").Render(context.Background(), &buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSettings_FullPageRender benchmarks complete Settings page rendering.
func BenchmarkSettings_FullPageRender(b *testing.B) {
	props := SettingsPageProps{
		ActiveTab: "general",
		CSRFToken: "test-token",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := Settings(props).Render(context.Background(), &buf); err != nil {
			b.Fatal(err)
		}
	}
}
