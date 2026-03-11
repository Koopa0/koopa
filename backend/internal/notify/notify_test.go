package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

// stubNotifier is a test double for Notifier.
type stubNotifier struct {
	err error
}

func (s *stubNotifier) Send(_ context.Context, _ string) error {
	return s.err
}
