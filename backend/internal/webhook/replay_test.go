package webhook

import (
	"testing"
	"time"
)

func TestDeduplicationCache_Seen(t *testing.T) {
	c := NewDeduplicationCache(10 * time.Minute)
	defer c.Stop()

	tests := []struct {
		name string
		key  string
		want bool
	}{
		{name: "first time", key: "delivery-1", want: false},
		{name: "duplicate", key: "delivery-1", want: true},
		{name: "different key", key: "delivery-2", want: false},
		{name: "duplicate of second", key: "delivery-2", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.Seen(tt.key)
			if got != tt.want {
				t.Errorf("Seen(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestDeduplicationCache_TTLExpiry(t *testing.T) {
	// TTL must be >= 2s so cleanup interval (max(ttl/2, 1s)) fires in time.
	ttl := 2 * time.Second
	c := NewDeduplicationCache(ttl)
	defer c.Stop()

	if c.Seen("key-1") {
		t.Fatal("Seen(\"key-1\") = true on first call, want false")
	}
	if !c.Seen("key-1") {
		t.Fatal("Seen(\"key-1\") = false on second call, want true")
	}

	// Wait for TTL + one cleanup interval + margin.
	time.Sleep(ttl + 1500*time.Millisecond)

	// After expiry + cleanup, the key should be accepted again.
	if c.Seen("key-1") {
		t.Error("Seen(\"key-1\") = true after TTL expiry, want false")
	}
}

func TestValidateTimestamp(t *testing.T) {
	maxSkew := 5 * time.Minute

	tests := []struct {
		name      string
		timestamp string
		wantErr   bool
	}{
		{
			name:      "current time",
			timestamp: time.Now().UTC().Format(time.RFC3339),
		},
		{
			name:      "2 minutes ago",
			timestamp: time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339),
		},
		{
			name:      "2 minutes in future",
			timestamp: time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339),
		},
		{
			name:      "10 minutes ago",
			timestamp: time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339),
			wantErr:   true,
		},
		{
			name:      "10 minutes in future",
			timestamp: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
			wantErr:   true,
		},
		{
			name:      "invalid format",
			timestamp: "not-a-timestamp",
			wantErr:   true,
		},
		{
			name:      "empty string",
			timestamp: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTimestamp(tt.timestamp, maxSkew)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateTimestamp(%q) = nil, want error", tt.timestamp)
				}
				return
			}
			if err != nil {
				t.Errorf("ValidateTimestamp(%q) unexpected error: %v", tt.timestamp, err)
			}
		})
	}
}
