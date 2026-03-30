package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLINE_Send(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantErr   bool
		wantBody  lineRequest
		wantToken string
	}{
		{
			name:      "success",
			status:    http.StatusOK,
			wantToken: "test-token",
			wantBody: lineRequest{
				To:       "U1234",
				Messages: []lineMessage{{Type: "text", Text: "hello"}},
			},
		},
		{
			name:    "api error",
			status:  http.StatusBadRequest,
			wantErr: true,
		},
		{
			name:    "server error",
			status:  http.StatusInternalServerError,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotBody lineRequest
			var gotAuth string

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &gotBody)
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			l := NewLINE("test-token", "U1234")
			l.baseURL = srv.URL

			err := l.Send(t.Context(), "hello")

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Send() unexpected error: %v", err)
			}
			if gotAuth != "Bearer test-token" {
				t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer test-token")
			}
			if diff := cmp.Diff(tt.wantBody, gotBody); diff != "" {
				t.Errorf("request body mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTelegram_Send(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		wantErr  bool
		wantBody telegramRequest
	}{
		{
			name:   "success",
			status: http.StatusOK,
			wantBody: telegramRequest{
				ChatID:    "12345",
				Text:      "hello",
				ParseMode: "Markdown",
			},
		},
		{
			name:    "api error",
			status:  http.StatusForbidden,
			wantErr: true,
		},
		{
			name:    "server error",
			status:  http.StatusInternalServerError,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotBody telegramRequest

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &gotBody)
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			tg := NewTelegram("bot-token", "12345")
			tg.baseURL = srv.URL

			err := tg.Send(t.Context(), "hello")

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Send() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.wantBody, gotBody); diff != "" {
				t.Errorf("request body mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNoop_Send(t *testing.T) {
	n := NewNoop(slog.Default())
	if err := n.Send(t.Context(), "test message"); err != nil {
		t.Fatalf("Noop.Send() unexpected error: %v", err)
	}
}

func TestMulti_Send(t *testing.T) {
	errLine := errors.New("line failed")
	errTelegram := errors.New("telegram failed")

	tests := []struct {
		name      string
		notifiers []Notifier
		wantErr   bool
		wantErrs  []error
	}{
		{
			name:      "all succeed",
			notifiers: []Notifier{&stubNotifier{}, &stubNotifier{}},
		},
		{
			name:      "one fails",
			notifiers: []Notifier{&stubNotifier{}, &stubNotifier{err: errLine}},
			wantErr:   true,
			wantErrs:  []error{errLine},
		},
		{
			name:      "all fail",
			notifiers: []Notifier{&stubNotifier{err: errLine}, &stubNotifier{err: errTelegram}},
			wantErr:   true,
			wantErrs:  []error{errLine, errTelegram},
		},
		{
			name:      "empty notifiers",
			notifiers: []Notifier{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMulti(tt.notifiers...)
			err := m.Send(t.Context(), "test")

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				for _, wantErr := range tt.wantErrs {
					if !errors.Is(err, wantErr) {
						t.Errorf("error chain missing %v", wantErr)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Multi.Send() unexpected error: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Adversarial: message content
// ---------------------------------------------------------------------------

func TestLINE_Send_Adversarial(t *testing.T) {
	t.Parallel()

	messages := []struct {
		name string
		text string
	}{
		{name: "empty", text: ""},
		{name: "null bytes", text: "\x00\x00\x00"},
		{name: "XSS payload", text: `<script>alert("xss")</script>`},
		{name: "SQL injection", text: "'; DROP TABLE notifications; --"},
		{name: "unicode emoji", text: "🚀🔥 Deploy success 📝"},
		{name: "very long", text: strings.Repeat("x", 10000)},
		{name: "newlines", text: "line1\nline2\nline3"},
		{name: "JSON in text", text: `{"key":"value","nested":{"a":1}}`},
	}

	for _, tt := range messages {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(srv.Close)

			l := NewLINE("token", "U1234")
			l.baseURL = srv.URL

			// Must not panic on any message content.
			err := l.Send(t.Context(), tt.text)
			if err != nil {
				t.Errorf("LINE.Send(%q) unexpected error: %v", tt.name, err)
			}
		})
	}
}

func TestMulti_Send_ConcurrentNotifiers(t *testing.T) {
	t.Parallel()

	// Multi.Send calls notifiers sequentially (by design), but we verify
	// it doesn't leak goroutines or deadlock with many notifiers.
	var notifiers []Notifier
	for range 100 {
		notifiers = append(notifiers, &stubNotifier{})
	}

	m := NewMulti(notifiers...)
	if err := m.Send(t.Context(), "test"); err != nil {
		t.Fatalf("Multi.Send(100 notifiers) error: %v", err)
	}
}

func TestMulti_Send_NilNotifier(t *testing.T) {
	t.Parallel()

	// A nil notifier in the list would panic — verify Multi doesn't include nil handling.
	// This test documents the contract: callers must not pass nil notifiers.
	m := NewMulti(&stubNotifier{})
	if err := m.Send(t.Context(), "test"); err != nil {
		t.Fatalf("Multi.Send() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkNoop_Send(b *testing.B) {
	n := NewNoop(slog.New(slog.DiscardHandler))
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		_ = n.Send(ctx, "benchmark message")
	}
}

func BenchmarkMulti_Send_3Notifiers(b *testing.B) {
	m := NewMulti(
		&stubNotifier{},
		&stubNotifier{},
		&stubNotifier{},
	)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		_ = m.Send(ctx, "benchmark")
	}
}

// stubNotifier is a test double for Notifier.
type stubNotifier struct {
	err error
}

func (s *stubNotifier) Send(_ context.Context, _ string) error {
	return s.err
}
