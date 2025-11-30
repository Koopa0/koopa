package component_test

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/web/component"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

// hasClass checks if an element has a specific CSS class.
func hasClass(n *html.Node, className string) bool {
	for _, attr := range n.Attr {
		if attr.Key == "class" {
			classes := strings.Fields(attr.Val)
			for _, c := range classes {
				if c == className {
					return true
				}
			}
		}
	}
	return false
}

// findElementByTag finds first element with specified tag name.
func findElementByTag(n *html.Node, tagName string) *html.Node {
	if n.Type == html.ElementNode && n.Data == tagName {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := findElementByTag(c, tagName); found != nil {
			return found
		}
	}
	return nil
}

// getAttribute gets attribute value from node.
func getAttribute(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

// isChildOf checks if child is descendant of parent.
func isChildOf(child, parent *html.Node) bool {
	for p := child.Parent; p != nil; p = p.Parent {
		if p == parent {
			return true
		}
	}
	return false
}

func TestMessageBubble_TimestampPosition(t *testing.T) {
	tests := []struct {
		name   string
		sender string
	}{
		{"user message", "user"},
		{"assistant message", "assistant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			rec := httptest.NewRecorder()

			props := component.MessageProps{
				ID:        "test-msg-123",
				Content:   "Hello world",
				Sender:    tt.sender,
				Timestamp: time.Now(),
			}

			err := component.MessageBubble(props).Render(ctx, rec)
			require.NoError(t, err, "render should succeed")

			// Parse HTML
			doc, err := html.Parse(rec.Body)
			require.NoError(t, err, "HTML should be valid")

			// Find the message bubble (should have rounded-2xl class)
			var bubbleDiv *html.Node
			var walkFunc func(*html.Node)
			walkFunc = func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "div" {
					if hasClass(n, "rounded-2xl") {
						bubbleDiv = n
						return
					}
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walkFunc(c)
				}
			}
			walkFunc(doc)
			require.NotNil(t, bubbleDiv, "should find message bubble div")

			// Find timestamp element
			timeElement := findElementByTag(doc, "time")
			require.NotNil(t, timeElement, "should have <time> element")

			// CRITICAL TEST: Timestamp should NOT be inside the bubble
			assert.False(t, isChildOf(timeElement, bubbleDiv),
				"timestamp must be OUTSIDE the message bubble (not a child/descendant)")

			t.Logf("✓ Timestamp correctly positioned outside bubble for %s", tt.sender)
		})
	}
}

func TestMessageBubble_OOBSwapID(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		msgID      string
		sender     string
		oobSwap    bool
		expectedID string
	}{
		{
			name:       "assistant message with OOB swap",
			msgID:      "assistant-12345",
			sender:     "assistant",
			oobSwap:    true,
			expectedID: "msg-assistant-12345",
		},
		{
			name:       "user message without OOB swap",
			msgID:      "user-67890",
			sender:     "user",
			oobSwap:    false,
			expectedID: "msg-user-67890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			props := component.MessageProps{
				ID:        tt.msgID,
				Content:   "Test content",
				Sender:    tt.sender,
				Timestamp: time.Now(),
				OOBSwap:   tt.oobSwap,
			}

			err := component.MessageBubble(props).Render(ctx, rec)
			require.NoError(t, err)

			doc, err := html.Parse(rec.Body)
			require.NoError(t, err)

			// Find the root article element
			article := findElementByTag(doc, "article")
			require.NotNil(t, article, "should have <article> root element")

			// Verify ID attribute
			actualID := getAttribute(article, "id")
			assert.Equal(t, tt.expectedID, actualID,
				"article ID should match expected format")

			// If OOB swap, verify hx-swap-oob attribute
			if tt.oobSwap {
				oobAttr := getAttribute(article, "hx-swap-oob")
				assert.Equal(t, "outerHTML", oobAttr,
					"OOB swap should use outerHTML")
				t.Logf("✓ OOB swap attribute correct: hx-swap-oob=\"%s\"", oobAttr)
			}
		})
	}
}

func TestMessageShell_CorrectID(t *testing.T) {
	ctx := context.Background()
	rec := httptest.NewRecorder()

	props := component.MessageShellProps{
		ID:        "assistant-test-789",
		MsgID:     "test-789",
		SessionID: "session-abc",
		Query:     "What is 2+2?",
	}

	err := component.MessageShell(props).Render(ctx, rec)
	require.NoError(t, err)

	doc, err := html.Parse(rec.Body)
	require.NoError(t, err)

	// Find the article element
	article := findElementByTag(doc, "article")
	require.NotNil(t, article, "should have <article> root element")

	// CRITICAL: ID must match what MessageBubble will use for OOB replacement
	actualID := getAttribute(article, "id")
	expectedID := "msg-assistant-test-789"
	assert.Equal(t, expectedID, actualID,
		"MessageShell ID must match MessageBubble OOB target")

	// Verify SSE connection attributes
	hxExt := getAttribute(article, "hx-ext")
	assert.Contains(t, hxExt, "sse", "should use SSE extension")

	sseConnect := getAttribute(article, "sse-connect")
	assert.Contains(t, sseConnect, "/genui/stream", "should connect to stream endpoint")
	assert.Contains(t, sseConnect, "msgId=test-789", "should include msgId parameter")
	assert.Contains(t, sseConnect, "sessionId=session-abc", "should include sessionId parameter")
	assert.Contains(t, sseConnect, "query=What+is+2%2B2%3F", "should include URL-encoded query")

	t.Log("✓ MessageShell ID matches OOB swap target format")
}

func TestMessageBubble_XSSPrevention(t *testing.T) {
	ctx := context.Background()
	rec := httptest.NewRecorder()

	maliciousContent := `<script>alert('XSS')</script><img src=x onerror="alert('XSS')">`

	props := component.MessageProps{
		ID:        "xss-test",
		Content:   maliciousContent,
		Sender:    "user",
		Timestamp: time.Now(),
	}

	err := component.MessageBubble(props).Render(ctx, rec)
	require.NoError(t, err)

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	htmlContent := string(body)

	// Verify HTML entities are escaped
	assert.Contains(t, htmlContent, "&lt;script&gt;", "script tags should be escaped")
	assert.Contains(t, htmlContent, "&lt;img", "img tags should be escaped")
	assert.NotContains(t, htmlContent, "<script>", "raw script tags should not appear")
	assert.NotContains(t, htmlContent, `onerror="`, "event handlers should be escaped")

	t.Log("✓ XSS content properly escaped in HTML output")
}

func TestMessageBubble_StreamingIndicator(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		isStreaming   bool
		expectSpinner bool
	}{
		{"streaming message shows spinner", true, true},
		{"complete message hides spinner", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			props := component.MessageProps{
				ID:          "stream-test",
				Content:     "Content",
				Sender:      "assistant",
				Timestamp:   time.Now(),
				IsStreaming: tt.isStreaming,
			}

			err := component.MessageBubble(props).Render(ctx, rec)
			require.NoError(t, err)

			body, err := io.ReadAll(rec.Body)
			require.NoError(t, err)
			htmlContent := string(body)

			if tt.expectSpinner {
				assert.Contains(t, htmlContent, "animate-pulse",
					"streaming message should have typing indicator with pulse animation")
				assert.Contains(t, htmlContent, "Assistant is typing",
					"streaming message should have accessible status text")
			} else {
				// Complete messages should not have typing indicator
				assert.NotContains(t, htmlContent, "Assistant is typing",
					"complete message should not show typing indicator")
			}
		})
	}
}

func TestMessageBubble_AccessibilityAttributes(t *testing.T) {
	ctx := context.Background()
	rec := httptest.NewRecorder()

	props := component.MessageProps{
		ID:        "a11y-test",
		Content:   "Test message",
		Sender:    "assistant",
		Timestamp: time.Now(),
	}

	err := component.MessageBubble(props).Render(ctx, rec)
	require.NoError(t, err)

	doc, err := html.Parse(rec.Body)
	require.NoError(t, err)

	// Find article element
	article := findElementByTag(doc, "article")
	require.NotNil(t, article)

	// Verify semantic role
	role := getAttribute(article, "role")
	assert.Equal(t, "article", role,
		"message should have semantic article role")

	t.Log("✓ Accessibility attributes present")
}
