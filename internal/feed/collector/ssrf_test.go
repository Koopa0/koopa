// Copyright 2026 Koopa. All rights reserved.

package collector

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsInternalIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"ipv4 loopback", "127.0.0.1", true},
		{"ipv4 loopback range", "127.9.9.9", true},
		{"private 10", "10.0.0.1", true},
		{"private 172.16", "172.16.0.1", true},
		{"private 172.31", "172.31.255.255", true},
		{"private 192.168", "192.168.1.1", true},
		{"cgnat 100.64", "100.64.0.1", true},
		{"cgnat 100.127", "100.127.255.255", true},
		{"link-local metadata", "169.254.169.254", true},
		{"link-local", "169.254.0.1", true},
		{"unspecified v4", "0.0.0.0", true},
		{"ipv6 loopback", "::1", true},
		{"ipv6 ula", "fd00::1", true},
		{"ipv6 link-local", "fe80::1", true},
		{"ipv6 unspecified", "::", true},
		{"ipv4-mapped loopback", "::ffff:127.0.0.1", true},
		{"public dns", "8.8.8.8", false},
		{"public cloudflare", "1.1.1.1", false},
		{"public 172.32 not private", "172.32.0.1", false},
		{"public 11", "11.0.0.1", false},
		{"public ipv6", "2606:4700:4700::1111", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("ParseIP(%q) = nil", tt.ip)
			}
			if got := isInternalIP(ip); got != tt.want {
				t.Errorf("isInternalIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// TestGuardedDialContext_BlocksLoopback proves the dial guard refuses a real
// connection to a loopback address end-to-end: httptest binds 127.0.0.1, and
// the collector's client must fail to reach it (no DNS rebinding or encoding
// trick required — the IP is checked at connect time).
func TestGuardedDialContext_BlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer c.Stop()

	resp, err := c.client.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("Get(%s) succeeded, want refusal (loopback must be blocked)", srv.URL)
	}
	if !strings.Contains(err.Error(), "internal address") {
		t.Errorf("Get(%s) err = %v, want an 'internal address' refusal", srv.URL, err)
	}
}
