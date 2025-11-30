package component

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSidebar_SessionList verifies sidebar with session list rendering.
func TestSidebar_SessionList(t *testing.T) {
	t.Parallel()
	sessions := []SessionItem{
		{ID: uuid.New(), Title: "Session 1", UpdatedAt: time.Now()},
		{ID: uuid.New(), Title: "Session 2", UpdatedAt: time.Now().Add(-1 * time.Hour)},
	}

	props := SidebarProps{
		Sessions:  sessions,
		ActiveID:  sessions[0].ID,
		IsOpen:    false,
		CSRFToken: "test-token",
	}

	var buf bytes.Buffer
	err := Sidebar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "Session 1")
	assert.Contains(t, html, "Session 2")
	assert.Contains(t, html, `id="session-list"`)      // OOB swap target
	assert.Contains(t, html, `@keydown.escape.window`) // Keyboard nav
	assert.Contains(t, html, `x-trap`)                 // Focus trap
	assert.Contains(t, html, `aria-label="Session navigation"`)
}

// TestSidebar_EmptySessionList verifies empty state rendering.
func TestSidebar_EmptySessionList(t *testing.T) {
	t.Parallel()
	props := SidebarProps{
		Sessions:  []SessionItem{}, // Empty list
		CSRFToken: "test-token",
	}

	var buf bytes.Buffer
	err := Sidebar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "No sessions yet") // Empty state message
}

// TestSidebar_NilSessionList verifies nil session list handling.
func TestSidebar_NilSessionList(t *testing.T) {
	t.Parallel()
	props := SidebarProps{
		Sessions:  nil, // Nil list
		CSRFToken: "test-token",
	}

	var buf bytes.Buffer
	err := Sidebar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "No sessions yet") // Same as empty
}

// TestSidebar_ActiveSessionHighlighted verifies active session styling.
func TestSidebar_ActiveSessionHighlighted(t *testing.T) {
	t.Parallel()
	activeID := uuid.New()
	sessions := []SessionItem{
		{ID: activeID, Title: "Active Session"},
		{ID: uuid.New(), Title: "Inactive Session"},
	}

	props := SidebarProps{
		Sessions:  sessions,
		ActiveID:  activeID,
		CSRFToken: "test-token",
	}

	var buf bytes.Buffer
	err := Sidebar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "bg-primary-100")     // Active state background
	assert.Contains(t, html, "border-primary-600") // Active state border
}

// TestSidebar_MobileOverlayOpen verifies mobile overlay when IsOpen=true.
func TestSidebar_MobileOverlayOpen(t *testing.T) {
	t.Parallel()
	props := SidebarProps{
		Sessions:  []SessionItem{},
		IsOpen:    true, // Mobile overlay open
		CSRFToken: "test-token",
	}

	var buf bytes.Buffer
	err := Sidebar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "bg-black/50 backdrop-blur-sm") // Backdrop
	assert.Contains(t, html, "md:hidden")                    // Mobile only
}

// TestSidebar_MobileOverlayClosed verifies no backdrop when IsOpen=false.
func TestSidebar_MobileOverlayClosed(t *testing.T) {
	t.Parallel()
	props := SidebarProps{
		Sessions:  []SessionItem{},
		IsOpen:    false, // Mobile overlay closed
		CSRFToken: "test-token",
	}

	var buf bytes.Buffer
	err := Sidebar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	// Backdrop div should not be present
	assert.NotContains(t, html, "bg-black/50 backdrop-blur-sm")
}

// TestSidebar_NewSessionButton verifies New Session button rendering.
func TestSidebar_NewSessionButton(t *testing.T) {
	t.Parallel()
	props := SidebarProps{
		Sessions:  []SessionItem{},
		CSRFToken: "test-token",
	}

	var buf bytes.Buffer
	err := Sidebar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "New Chat")
	assert.Contains(t, html, `action="/genui/sessions"`) // Progressive enhancement
	assert.Contains(t, html, `method="POST"`)
	assert.Contains(t, html, `hx-post="/genui/sessions"`) // HTMX enhancement
}

// TestSessionListItem_InvalidUUID verifies rendering with invalid UUID.
func TestSessionListItem_InvalidUUID(t *testing.T) {
	t.Parallel()
	props := SessionItemProps{
		Session: SessionItem{
			ID:    uuid.Nil, // Invalid UUID
			Title: "Test",
		},
		Active: false,
	}

	var buf bytes.Buffer
	err := SessionListItem(props).Render(context.Background(), &buf)
	require.NoError(t, err, "Should render without panic")

	html := buf.String()
	assert.Contains(t, html, "00000000-0000-0000-0000-000000000000") // Renders Nil UUID
}

// TestSessionListItem_EmptyTitle verifies rendering with empty title.
func TestSessionListItem_EmptyTitle(t *testing.T) {
	t.Parallel()
	props := SessionItemProps{
		Session: SessionItem{
			ID:    uuid.New(),
			Title: "", // Empty title
		},
		Active: false,
	}

	var buf bytes.Buffer
	err := SessionListItem(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "New Chat") // Placeholder for empty title
}

// TestSessionListItem_ZeroTimestamp verifies rendering with zero timestamp.
func TestSessionListItem_ZeroTimestamp(t *testing.T) {
	t.Parallel()
	props := SessionItemProps{
		Session: SessionItem{
			ID:        uuid.New(),
			Title:     "Test Session",
			UpdatedAt: time.Time{}, // Zero value
		},
		Active: false,
	}

	var buf bytes.Buffer
	err := SessionListItem(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "Just now") // Placeholder for zero timestamp
}

// TestSessionListItem_DeleteButton verifies delete button rendering.
func TestSessionListItem_DeleteButton(t *testing.T) {
	t.Parallel()
	sessionID := uuid.New()
	props := SessionItemProps{
		Session: SessionItem{
			ID:    sessionID,
			Title: "Test Session",
		},
		Active: false,
	}

	var buf bytes.Buffer
	err := SessionListItem(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, `hx-delete="/genui/sessions/`+sessionID.String()+`"`)
	assert.Contains(t, html, `hx-confirm="Delete this session?"`)
	assert.Contains(t, html, `min-w-[44px] min-h-[44px]`) // Touch target
	assert.Contains(t, html, `aria-label="Delete session"`)
}

// TestSessionListItem_HTMXAttributes verifies session links use query parameters, NOT HTMX partial loading.
// CRITICAL: Session switching should reload the entire page to avoid nested UI bug.
func TestSessionListItem_HTMXAttributes(t *testing.T) {
	t.Parallel()
	sessionID := uuid.New()
	props := SessionItemProps{
		Session: SessionItem{
			ID:    sessionID,
			Title: "Test",
		},
		Active: false,
	}

	var buf bytes.Buffer
	err := SessionListItem(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()

	// CORRECT behavior: Query parameter format
	assert.Contains(t, html, `href="/genui?session=`+sessionID.String()+`"`,
		"session link should use query parameter format")

	// CORRECT behavior: NO HTMX partial loading (prevents nesting bug)
	assert.NotContains(t, html, `hx-get="/genui/sessions/`,
		"session link should NOT use HTMX partial loading")
	assert.NotContains(t, html, `hx-target="#message-list"`,
		"session link should NOT target message-list (causes nesting)")
	assert.NotContains(t, html, `hx-swap="innerHTML"`,
		"session link should NOT use HTMX swap (full page reload instead)")
}

// TestSessionListItem_ActiveState verifies active session styling.
func TestSessionListItem_ActiveState(t *testing.T) {
	t.Parallel()
	props := SessionItemProps{
		Session: SessionItem{
			ID:    uuid.New(),
			Title: "Active Session",
		},
		Active: true, // Active state
	}

	var buf bytes.Buffer
	err := SessionListItem(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "bg-primary-100")     // Active background
	assert.Contains(t, html, "border-primary-600") // Active border
}

// TestSidebar_AlpineJSAttributes verifies Alpine.js state management.
func TestSidebar_AlpineJSAttributes(t *testing.T) {
	t.Parallel()
	props := SidebarProps{
		Sessions:  []SessionItem{},
		IsOpen:    true,
		CSRFToken: "test-token",
	}

	var buf bytes.Buffer
	err := Sidebar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, `x-data`)
	assert.Contains(t, html, `x-effect`)
	assert.Contains(t, html, `x-trap`)
	assert.Contains(t, html, `:aria-expanded`)
}
