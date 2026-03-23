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

const telegramDefaultURL = "https://api.telegram.org"

// Telegram sends messages via the Telegram Bot API.
type Telegram struct {
	token   string // bot token
	chatID  string // recipient chat ID
	client  *http.Client
	baseURL string // overridden in tests
}

// NewTelegram returns a Telegram notifier.
func NewTelegram(token, chatID string) *Telegram {
	return &Telegram{
		token:   token,
		chatID:  chatID,
		client:  &http.Client{Timeout: 15 * time.Second},
		baseURL: telegramDefaultURL,
	}
}

// telegramRequest is the Telegram sendMessage request body.
type telegramRequest struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

// Send posts a text message via the Telegram Bot API.
func (t *Telegram) Send(ctx context.Context, text string) error {
	body, err := json.Marshal(telegramRequest{
		ChatID:    t.chatID,
		Text:      text,
		ParseMode: "Markdown",
	})
	if err != nil {
		return fmt.Errorf("marshaling telegram request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", t.baseURL, t.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending telegram notification: %w", err)
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body) // drain for keep-alive
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram api returned status %d", resp.StatusCode)
	}
	return nil
}
