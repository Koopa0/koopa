// Package security provides security validators for Koopa.
//
// URL validator prevents SSRF (Server-Side Request Forgery) attacks by blocking
// requests to private networks, cloud metadata endpoints, and other dangerous targets.

package security

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// URL validates URLs to prevent SSRF attacks.
//
// Blocked targets:
//   - Private IP ranges (RFC 1918): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
//   - Loopback: 127.0.0.0/8, ::1
//   - Link-local: 169.254.0.0/16, fe80::/10
//   - Cloud metadata: 169.254.169.254
//   - Known dangerous hostnames: localhost, metadata.google.internal
//
// Usage:
//
//	validator := security.NewURL()
//	if err := validator.Validate("http://example.com"); err != nil {
//	    // URL is not safe
//	}
//
//	// Or use SafeTransport for automatic DNS resolution checking:
//	client := &http.Client{Transport: validator.SafeTransport()}
type URL struct {
	// allowedSchemes defines permitted URL schemes
	allowedSchemes map[string]struct{}

	// blockedHosts defines hostnames that are always blocked
	blockedHosts map[string]struct{}
}

// NewURL creates a new URL validator with default security settings.
func NewURL() *URL {
	return &URL{
		allowedSchemes: map[string]struct{}{
			"http":  {},
			"https": {},
		},
		blockedHosts: map[string]struct{}{
			"localhost":                {},
			"metadata.google.internal": {},
			"metadata.gce.internal":    {},
			"metadata.internal":        {},
		},
	}
}

// Validate checks if a URL is safe to fetch.
// Returns an error if the URL targets a private network or blocked host.
//
// Note: This performs static validation only. For complete SSRF protection
// during DNS resolution, use SafeTransport() instead.
func (v *URL) Validate(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Check scheme
	if _, ok := v.allowedSchemes[strings.ToLower(u.Scheme)]; !ok {
		return fmt.Errorf("unsupported scheme: %s (allowed: http, https)", u.Scheme)
	}

	// Check host
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("empty hostname")
	}

	return v.validateHost(host)
}

// validateHost checks if a hostname is safe.
func (v *URL) validateHost(host string) error {
	hostLower := strings.ToLower(host)

	// Check blocked hostnames
	if _, blocked := v.blockedHosts[hostLower]; blocked {
		return fmt.Errorf("blocked host: %s", host)
	}

	// Check if host is an IP address
	ip := net.ParseIP(host)
	if ip != nil {
		return v.checkIP(ip)
	}

	// Hostname (not IP) - DNS resolution check happens in SafeTransport
	return nil
}

// checkIP validates that an IP address is not in a blocked range.
func (v *URL) checkIP(ip net.IP) error {
	// Normalize IPv6-mapped IPv4 addresses (::ffff:127.0.0.1 -> 127.0.0.1)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// Check loopback (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return fmt.Errorf("loopback address not allowed: %s", ip)
	}

	// Check private networks (RFC 1918 + IPv6 private)
	if ip.IsPrivate() {
		return fmt.Errorf("private IP not allowed: %s", ip)
	}

	// Check link-local (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("link-local address not allowed: %s", ip)
	}

	// Check unspecified (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return fmt.Errorf("unspecified address not allowed: %s", ip)
	}

	// Explicitly check cloud metadata endpoint (169.254.169.254)
	// This is technically link-local but we check explicitly for clarity
	if ip.String() == "169.254.169.254" {
		return fmt.Errorf("cloud metadata endpoint blocked: %s", ip)
	}

	return nil
}

// SafeTransport returns an http.Transport that validates IP addresses
// during DNS resolution to prevent SSRF via DNS rebinding.
//
// This provides stronger protection than Validate() alone because it
// checks the actual resolved IP addresses, not just the hostname.
//
// Usage:
//
//	validator := security.NewURL()
//	client := &http.Client{Transport: validator.SafeTransport()}
func (v *URL) SafeTransport() *http.Transport {
	return &http.Transport{
		DialContext: v.safeDialContext,
		// Reasonable defaults
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// safeDialContext is a custom dialer that validates resolved IPs before connecting.
func (v *URL) safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Parse host and port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// addr might not have a port (shouldn't happen with http.Transport)
		host = addr
		port = ""
	}

	// Check if host is already an IP
	if ip := net.ParseIP(host); ip != nil {
		if err := v.checkIP(ip); err != nil {
			return nil, fmt.Errorf("SSRF blocked: %w", err)
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	// Resolve DNS and check all returned IPs
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	// Check all resolved IPs
	for _, ip := range ips {
		if err := v.checkIP(ip); err != nil {
			return nil, fmt.Errorf("SSRF blocked (resolved %s -> %s): %w", host, ip, err)
		}
	}

	// All IPs are safe, proceed with connection
	// Use the first resolved IP to avoid TOCTOU issues
	if len(ips) > 0 {
		targetAddr := ips[0].String()
		if port != "" {
			targetAddr = net.JoinHostPort(targetAddr, port)
		}
		return (&net.Dialer{}).DialContext(ctx, network, targetAddr)
	}

	return nil, fmt.Errorf("no IP addresses resolved for %s", host)
}

// ValidateRedirect checks if a redirect URL is safe.
// This should be used in redirect handlers to prevent SSRF via redirects.
func (v *URL) ValidateRedirect(req *http.Request, via []*http.Request) error {
	// Limit redirect chain length
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}

	// Validate the redirect target
	return v.Validate(req.URL.String())
}
