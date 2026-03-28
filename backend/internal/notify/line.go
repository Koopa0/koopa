package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const lineDefaultURL = "https://api.line.me/v2/bot/message/push"

// LINE sends push messages via the LINE Messaging API.
type LINE struct {
	token   string // channel access token
	userID  string // recipient user ID
	client  *http.Client
	baseURL string // overridden in tests
}

// NewLINE returns a LINE notifier.
func NewLINE(token, userID string) *LINE {
	return &LINE{
		token:   token,
		userID:  userID,
		client:  &http.Client{Timeout: 10 * time.Second},
		baseURL: lineDefaultURL,
	}
}

// lineRequest is the LINE Messaging API push message request body.
type lineRequest struct {
	To       string        `json:"to"`
	Messages []lineMessage `json:"messages"`
}

// lineMessage is a single text message in a LINE push request.
type lineMessage struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Send pushes a text message via the LINE Messaging API.
func (l *LINE) Send(ctx context.Context, text string) error {
	body, err := json.Marshal(lineRequest{
		To:       l.userID,
		Messages: []lineMessage{{Type: "text", Text: text}},
	})
	if err != nil {
		return fmt.Errorf("marshaling line request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.baseURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating line request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+l.token)

	resp, err := l.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending line notification: %w", err)
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body) // drain for keep-alive
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("line api returned status %d", resp.StatusCode)
	}
	return nil
}
