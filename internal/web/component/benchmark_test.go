package component

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// BenchmarkSidebar_Render100Sessions benchmarks sidebar with 100 sessions.
//
// Performance target: <10ms per render
// Allocation target: <500 allocs/op
func BenchmarkSidebar_Render100Sessions(b *testing.B) {
	sessions := generateTestSessions(100)
	props := SidebarProps{
		Sessions:  sessions,
		ActiveID:  sessions[0].ID,
		CSRFToken: "test-token",
	}

	b.ResetTimer()
	b.ReportAllocs()

	var elapsed time.Duration
	for i := 0; i < b.N; i++ {
		start := time.Now()
		var buf bytes.Buffer
		if err := Sidebar(props).Render(context.Background(), &buf); err != nil {
			b.Fatal(err)
		}
		elapsed += time.Since(start)
	}

	// Performance target: <10ms per render (on M1 Max, 10 cores)
	// Allocation target: <500 allocs/op
	// Check results with: go test -bench=BenchmarkSidebar_Render100Sessions -benchmem
}

// BenchmarkSidebar_Render1000Sessions benchmarks sidebar with 1000 sessions.
//
// Performance target: <100ms per render
func BenchmarkSidebar_Render1000Sessions(b *testing.B) {
	sessions := generateTestSessions(1000)
	props := SidebarProps{
		Sessions:  sessions,
		ActiveID:  sessions[0].ID,
		CSRFToken: "test-token",
	}

	b.ResetTimer()
	b.ReportAllocs()

	var elapsed time.Duration
	for i := 0; i < b.N; i++ {
		start := time.Now()
		var buf bytes.Buffer
		if err := Sidebar(props).Render(context.Background(), &buf); err != nil {
			b.Fatal(err)
		}
		elapsed += time.Since(start)
	}

	// Enforce performance target
	avgDuration := elapsed / time.Duration(b.N)
	if avgDuration > 100*time.Millisecond {
		b.Fatalf("Performance regression: 1000 sessions took %v (target: <100ms)", avgDuration)
	}
}

// BenchmarkSidebar_Render10000Sessions benchmarks sidebar with 10000 sessions.
//
// Performance target: <1s per render (may require pagination)
func BenchmarkSidebar_Render10000Sessions(b *testing.B) {
	sessions := generateTestSessions(10000)
	props := SidebarProps{
		Sessions:  sessions,
		ActiveID:  sessions[0].ID,
		CSRFToken: "test-token",
	}

	b.ResetTimer()
	b.ReportAllocs()

	var elapsed time.Duration
	for i := 0; i < b.N; i++ {
		start := time.Now()
		var buf bytes.Buffer
		if err := Sidebar(props).Render(context.Background(), &buf); err != nil {
			b.Fatal(err)
		}
		elapsed += time.Since(start)
	}

	// Enforce performance target (may require pagination)
	avgDuration := elapsed / time.Duration(b.N)
	if avgDuration > 1*time.Second {
		b.Fatalf("Performance regression: 10000 sessions took %v (target: <1s or implement pagination)", avgDuration)
	}
}

// BenchmarkNavbar_Render benchmarks navbar rendering.
//
// Allocation target: <100 allocs/op
func BenchmarkNavbar_Render(b *testing.B) {
	props := NavbarProps{
		AppName:    "Koopa",
		UserName:   "demo-user",
		ActivePath: "/genui/settings",
		CSRFToken:  "test-token",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := Navbar(props).Render(context.Background(), &buf); err != nil {
			b.Fatal(err)
		}
	}

	// Performance target: <1ms per render
	// Allocation target: <100 allocs/op
	// Check results with: go test -bench=BenchmarkNavbar_Render -benchmem
}

// BenchmarkTabs_Render benchmarks tabs rendering.
func BenchmarkTabs_Render(b *testing.B) {
	props := TabsProps{
		Tabs: []TabItem{
			{ID: "general", Label: "General"},
			{ID: "security", Label: "Security"},
			{ID: "appearance", Label: "Appearance"},
		},
		ActiveID: "general",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := Tabs(props).Render(context.Background(), &buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSessionListItem_Render benchmarks single session item rendering.
func BenchmarkSessionListItem_Render(b *testing.B) {
	props := SessionItemProps{
		Session: SessionItem{
			ID:        uuid.New(),
			Title:     "Test Session with a reasonably long title",
			UpdatedAt: time.Now(),
		},
		Active: false,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := SessionListItem(props).Render(context.Background(), &buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkNavLink_Render benchmarks navigation link rendering.
func BenchmarkNavLink_Render(b *testing.B) {
	props := NavLinkProps{
		Href:   "/genui/settings",
		Label:  "Settings",
		Active: true,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := NavLink(props).Render(context.Background(), &buf); err != nil {
			b.Fatal(err)
		}
	}
}

// generateTestSessions creates n test sessions with realistic data.
func generateTestSessions(n int) []SessionItem {
	sessions := make([]SessionItem, n)
	for i := 0; i < n; i++ {
		sessions[i] = SessionItem{
			ID:        uuid.New(),
			Title:     fmt.Sprintf("Test Session %d with a reasonably long title that might truncate", i+1),
			UpdatedAt: time.Now().Add(-time.Duration(i) * time.Minute),
		}
	}
	return sessions
}
