package component_test

import (
	"context"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/web/component"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

func TestSessionListItem_LinkFormat(t *testing.T) {
	ctx := context.Background()
	rec := httptest.NewRecorder()

	sessionID := uuid.New()
	props := component.SessionItemProps{
		Session: component.SessionItem{
			ID:        sessionID,
			Title:     "Test Session",
			UpdatedAt: time.Now(),
		},
		Active: false,
	}

	err := component.SessionListItem(props).Render(ctx, rec)
	require.NoError(t, err)

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	htmlContent := string(body)

	// CRITICAL: Link should use query parameter format, NOT path parameter
	expectedHref := "/genui?session=" + sessionID.String()
	assert.Contains(t, htmlContent, expectedHref,
		"session link should use query parameter format")

	// CRITICAL: Should NOT have HTMX partial loading attributes
	assert.NotContains(t, htmlContent, "hx-get=",
		"session link should NOT use HTMX partial loading")
	assert.NotContains(t, htmlContent, `hx-target="#message-list"`,
		"should NOT target message-list (would cause nesting)")

	t.Logf("✓ Session link correctly formatted: %s", expectedHref)
}

func TestSessionListItem_NoHTMXPartialLoad(t *testing.T) {
	ctx := context.Background()
	rec := httptest.NewRecorder()

	sessionID := uuid.New()
	props := component.SessionItemProps{
		Session: component.SessionItem{
			ID:        sessionID,
			Title:     "Another Session",
			UpdatedAt: time.Now(),
		},
		Active: false,
	}

	err := component.SessionListItem(props).Render(ctx, rec)
	require.NoError(t, err)

	doc, err := html.Parse(rec.Body)
	require.NoError(t, err)

	// Find the <a> element
	var linkElement *html.Node
	var walkFunc func(*html.Node)
	walkFunc = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			linkElement = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkFunc(c)
		}
	}
	walkFunc(doc)
	require.NotNil(t, linkElement, "should have <a> element")

	// Verify NO HTMX attributes that would cause partial loading
	hxGet := getAttribute(linkElement, "hx-get")
	assert.Empty(t, hxGet, "should NOT have hx-get attribute")

	hxTarget := getAttribute(linkElement, "hx-target")
	assert.Empty(t, hxTarget, "should NOT have hx-target attribute")

	hxSwap := getAttribute(linkElement, "hx-swap")
	assert.Empty(t, hxSwap, "should NOT have hx-swap attribute")

	// Verify href uses query parameter
	href := getAttribute(linkElement, "href")
	assert.Contains(t, href, "/genui?session=",
		"href should use query parameter format")

	t.Log("✓ Session link is plain link without HTMX partial loading")
}

func TestSessionListItem_ActiveState(t *testing.T) {
	ctx := context.Background()

	sessionID := uuid.New()
	props := component.SessionItemProps{
		Session: component.SessionItem{
			ID:        sessionID,
			Title:     "Active Session",
			UpdatedAt: time.Now(),
		},
		Active: true,
	}

	rec := httptest.NewRecorder()
	err := component.SessionListItem(props).Render(ctx, rec)
	require.NoError(t, err)

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	htmlContent := string(body)

	// Active session should have visual indicator
	assert.Contains(t, htmlContent, "bg-primary-100",
		"active session should have primary background")
	assert.Contains(t, htmlContent, "border-primary-600",
		"active session should have primary border")

	t.Log("✓ Active session has correct visual styling")
}

func TestSessionListItem_DeleteButton(t *testing.T) {
	ctx := context.Background()
	rec := httptest.NewRecorder()

	sessionID := uuid.New()
	props := component.SessionItemProps{
		Session: component.SessionItem{
			ID:        sessionID,
			Title:     "Deletable Session",
			UpdatedAt: time.Now(),
		},
		Active: false,
	}

	err := component.SessionListItem(props).Render(ctx, rec)
	require.NoError(t, err)

	doc, err := html.Parse(rec.Body)
	require.NoError(t, err)

	// Find delete button
	var deleteButton *html.Node
	var walkFunc func(*html.Node)
	walkFunc = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "button" {
			// Check if it has hx-delete attribute
			for _, attr := range n.Attr {
				if attr.Key == "hx-delete" {
					deleteButton = n
					return
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkFunc(c)
		}
	}
	walkFunc(doc)
	require.NotNil(t, deleteButton, "should have delete button with hx-delete")

	// Verify HTMX delete attributes
	hxDelete := getAttribute(deleteButton, "hx-delete")
	expectedDeleteURL := "/genui/sessions/" + sessionID.String()
	assert.Equal(t, expectedDeleteURL, hxDelete,
		"delete button should target correct endpoint")

	hxConfirm := getAttribute(deleteButton, "hx-confirm")
	assert.NotEmpty(t, hxConfirm, "delete should have confirmation dialog")

	hxSwap := getAttribute(deleteButton, "hx-swap")
	assert.Equal(t, "none", hxSwap,
		"delete should not swap content (page will reload)")

	t.Log("✓ Delete button has correct HTMX attributes")
}

func TestSidebar_EmptyState(t *testing.T) {
	ctx := context.Background()
	rec := httptest.NewRecorder()

	props := component.SidebarProps{
		Sessions:  []component.SessionItem{}, // Empty list
		ActiveID:  uuid.Nil,
		IsOpen:    true,
		CSRFToken: "test-token",
	}

	err := component.Sidebar(props).Render(ctx, rec)
	require.NoError(t, err)

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	htmlContent := string(body)

	// Should show empty state message
	assert.Contains(t, htmlContent, "No sessions yet",
		"empty sidebar should show helpful message")

	// Should still show New Chat button
	assert.Contains(t, htmlContent, "New Chat",
		"empty sidebar should still have New Chat button")

	t.Log("✓ Empty sidebar shows appropriate message")
}

func TestSidebar_NewSessionButton(t *testing.T) {
	ctx := context.Background()
	rec := httptest.NewRecorder()

	props := component.SidebarProps{
		Sessions:  []component.SessionItem{},
		ActiveID:  uuid.Nil,
		IsOpen:    true,
		CSRFToken: "test-csrf-token",
	}

	err := component.Sidebar(props).Render(ctx, rec)
	require.NoError(t, err)

	doc, err := html.Parse(rec.Body)
	require.NoError(t, err)

	// Find form with POST to /genui/sessions
	var form *html.Node
	var walkFunc func(*html.Node)
	walkFunc = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			action := getAttribute(n, "action")
			if action == "/genui/sessions" {
				form = n
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkFunc(c)
		}
	}
	walkFunc(doc)
	require.NotNil(t, form, "should have form for creating new session")

	// Verify form method
	method := getAttribute(form, "method")
	assert.Equal(t, "POST", method, "new session form should use POST")

	// Find CSRF token input
	var csrfInput *html.Node
	walkFunc = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			name := getAttribute(n, "name")
			if name == "csrf_token" {
				csrfInput = n
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkFunc(c)
		}
	}
	walkFunc(form)
	require.NotNil(t, csrfInput, "form should have CSRF token input")

	csrfValue := getAttribute(csrfInput, "value")
	assert.Equal(t, "test-csrf-token", csrfValue,
		"CSRF token should match provided value")

	t.Log("✓ New Session button has correct form structure and CSRF protection")
}

func TestSidebar_MobileResponsive(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		isOpen         bool
		expectBackdrop bool
	}{
		{"sidebar closed on mobile", false, false},
		{"sidebar open on mobile", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			props := component.SidebarProps{
				Sessions:  []component.SessionItem{},
				ActiveID:  uuid.Nil,
				IsOpen:    tt.isOpen,
				CSRFToken: "test-token",
			}

			err := component.Sidebar(props).Render(ctx, rec)
			require.NoError(t, err)

			body, err := io.ReadAll(rec.Body)
			require.NoError(t, err)
			htmlContent := string(body)

			if tt.expectBackdrop {
				assert.Contains(t, htmlContent, "backdrop-blur",
					"open sidebar should have backdrop for mobile")
			}

			// Sidebar should always render (visibility controlled by CSS)
			assert.Contains(t, htmlContent, `id="sidebar"`,
				"sidebar element should always be present")
		})
	}
}

func TestSessionItem_TitleFallback(t *testing.T) {
	ctx := context.Background()
	rec := httptest.NewRecorder()

	sessionID := uuid.New()
	props := component.SessionItemProps{
		Session: component.SessionItem{
			ID:        sessionID,
			Title:     "", // Empty title
			UpdatedAt: time.Now(),
		},
		Active: false,
	}

	err := component.SessionListItem(props).Render(ctx, rec)
	require.NoError(t, err)

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	htmlContent := string(body)

	// Should show fallback text for empty title
	assert.Contains(t, htmlContent, "New Chat",
		"empty title should show 'New Chat' fallback")

	t.Log("✓ Empty session title shows fallback text")
}

func TestSessionItem_TimestampFormat(t *testing.T) {
	ctx := context.Background()
	rec := httptest.NewRecorder()

	sessionID := uuid.New()
	testTime := time.Date(2025, 11, 30, 15, 4, 0, 0, time.UTC)

	props := component.SessionItemProps{
		Session: component.SessionItem{
			ID:        sessionID,
			Title:     "Test Session",
			UpdatedAt: testTime,
		},
		Active: false,
	}

	err := component.SessionListItem(props).Render(ctx, rec)
	require.NoError(t, err)

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	htmlContent := string(body)

	// Timestamp should be formatted as "Nov 30, 15:04" (Jan 2, 15:04 format)
	assert.Contains(t, htmlContent, "Nov 30, 15:04",
		"should display formatted timestamp")

	t.Log("✓ Timestamp rendered in readable format")
}
