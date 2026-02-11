package security

import (
	"net"
	"strings"
	"testing"
)

func TestURL_Validate(t *testing.T) {
	v := NewURL()

	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string // substring to check in error message
	}{
		// Valid public URLs
		{
			name:    "valid https URL",
			url:     "https://example.com/page",
			wantErr: false,
		},
		{
			name:    "valid http URL",
			url:     "http://example.com/page",
			wantErr: false,
		},
		{
			name:    "valid URL with port",
			url:     "https://example.com:8080/api",
			wantErr: false,
		},

		// Invalid schemes
		{
			name:    "ftp scheme blocked",
			url:     "ftp://example.com/file",
			wantErr: true,
			errMsg:  "unsupported scheme",
		},
		{
			name:    "file scheme blocked",
			url:     "file:///etc/passwd",
			wantErr: true,
			errMsg:  "unsupported scheme",
		},
		{
			name:    "javascript scheme blocked",
			url:     "javascript:alert(1)",
			wantErr: true,
			errMsg:  "unsupported scheme",
		},

		// Blocked hostnames
		{
			name:    "localhost blocked",
			url:     "http://localhost/admin",
			wantErr: true,
			errMsg:  "blocked host",
		},
		{
			name:    "localhost with port blocked",
			url:     "http://localhost:8080/admin",
			wantErr: true,
			errMsg:  "blocked host",
		},
		{
			name:    "metadata.google.internal blocked",
			url:     "http://metadata.google.internal/computeMetadata/v1/",
			wantErr: true,
			errMsg:  "blocked host",
		},

		// Loopback IPs
		{
			name:    "127.0.0.1 blocked",
			url:     "http://127.0.0.1/admin",
			wantErr: true,
			errMsg:  "loopback",
		},
		{
			name:    "127.0.0.1 with port blocked",
			url:     "http://127.0.0.1:3000/api",
			wantErr: true,
			errMsg:  "loopback",
		},
		{
			name:    "127.1.2.3 blocked",
			url:     "http://127.1.2.3/",
			wantErr: true,
			errMsg:  "loopback",
		},

		// Private IPs (RFC 1918)
		{
			name:    "10.0.0.1 blocked",
			url:     "http://10.0.0.1/internal",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "172.16.0.1 blocked",
			url:     "http://172.16.0.1/internal",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "192.168.1.1 blocked",
			url:     "http://192.168.1.1/router",
			wantErr: true,
			errMsg:  "private IP",
		},

		// Cloud metadata endpoint
		{
			name:    "AWS metadata endpoint blocked",
			url:     "http://169.254.169.254/latest/meta-data/",
			wantErr: true,
			errMsg:  "link-local", // 169.254.x.x is link-local
		},

		// Link-local
		{
			name:    "link-local IP blocked",
			url:     "http://169.254.1.1/",
			wantErr: true,
			errMsg:  "link-local",
		},

		// IPv6
		{
			name:    "IPv6 loopback blocked",
			url:     "http://[::1]/admin",
			wantErr: true,
			errMsg:  "loopback",
		},

		// Edge cases
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
			errMsg:  "unsupported scheme", // empty URL has empty scheme
		},
		{
			name:    "malformed URL",
			url:     "://invalid",
			wantErr: true,
			errMsg:  "invalid URL",
		},
		{
			name:    "0.0.0.0 blocked",
			url:     "http://0.0.0.0/",
			wantErr: true,
			errMsg:  "unspecified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate(%q) expected error, got nil", tt.url)
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate(%q) error = %q, want error containing %q", tt.url, err.Error(), tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("Validate(%q) unexpected error: %v", tt.url, err)
			}
		})
	}
}

func TestURL_checkIP(t *testing.T) {
	v := NewURL()

	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		// Public IPs (should pass)
		{"public IPv4", "8.8.8.8", false},
		{"public IPv4 2", "1.1.1.1", false},
		{"public IPv4 3", "93.184.216.34", false}, // example.com

		// Private IPs (should fail)
		{"private 10.x", "10.0.0.1", true},
		{"private 172.16.x", "172.16.0.1", true},
		{"private 192.168.x", "192.168.1.1", true},

		// Loopback (should fail)
		{"loopback", "127.0.0.1", true},
		{"loopback range", "127.255.255.255", true},

		// Link-local (should fail)
		{"link-local", "169.254.1.1", true},
		{"cloud metadata", "169.254.169.254", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("parsing IP: %s", tt.ip)
			}
			err := v.checkIP(ip)
			if tt.wantErr && err == nil {
				t.Errorf("checkIP(%s) expected error, got nil", tt.ip)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("checkIP(%s) unexpected error: %v", tt.ip, err)
			}
		})
	}
}

func TestURL_SafeTransport(t *testing.T) {
	v := NewURL()
	transport := v.SafeTransport()

	if transport == nil {
		t.Fatal("SafeTransport() returned nil")
	}

	if transport.DialContext == nil {
		t.Error("SafeTransport() DialContext is nil")
	}

	// Verify SafeTransport blocks dangerous IPs at the dial level.
	// This tests DNS-rebinding protection: even if DNS resolves to a blocked IP,
	// the custom DialContext must reject the connection.
	tests := []struct {
		name    string
		addr    string
		wantSub string // expected substring in error message
	}{
		{name: "loopback", addr: "127.0.0.1:80", wantSub: "loopback"},
		{name: "private 10.x", addr: "10.0.0.1:80", wantSub: "private"},
		{name: "private 192.168.x", addr: "192.168.1.1:80", wantSub: "private"},
		{name: "link-local metadata", addr: "169.254.169.254:80", wantSub: "link-local"},
		{name: "IPv6 loopback", addr: "[::1]:80", wantSub: "loopback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := transport.DialContext(t.Context(), "tcp", tt.addr)
			if err == nil {
				t.Errorf("SafeTransport().DialContext(%q) = nil, want error", tt.addr)
				return
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("SafeTransport().DialContext(%q) error = %q, want error containing %q", tt.addr, err.Error(), tt.wantSub)
			}
		})
	}
}
