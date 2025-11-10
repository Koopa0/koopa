package security

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// HTTP validates HTTP requests to prevent SSRF attacks.
// Used to prevent SSRF (Server-Side Request Forgery) attacks.
type HTTP struct {
	maxResponseSize int64
	allowedSchemes  []string
}

// NewHTTP creates a new HTTP validator.
func NewHTTP() *HTTP {
	return &HTTP{
		maxResponseSize: 5 * 1024 * 1024, // 5MB
		allowedSchemes:  []string{"http", "https"},
	}
}

// ValidateURL validates whether a URL is safe
// Checks protocol, host, IP address ranges, etc.
func (v *HTTP) ValidateURL(urlStr string) error {
	// 1. Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// 2. Check protocol
	lowercasedScheme := strings.ToLower(parsedURL.Scheme)
	if !slices.Contains(v.allowedSchemes, lowercasedScheme) {
		return fmt.Errorf("disallowed protocol: %s (only http/https allowed)", parsedURL.Scheme)
	}

	// 3. Get hostname
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return fmt.Errorf("invalid hostname")
	}

	// 4. Check if it's a dangerous hostname
	if isDangerousHostname(hostname) {
		slog.Warn("SSRF attempt - dangerous hostname detected",
			"url", urlStr,
			"hostname", hostname,
			"security_event", "ssrf_dangerous_hostname")
		return fmt.Errorf("access denied: accessing internal networks or metadata services is not allowed")
	}

	// 5. Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("unable to resolve hostname: %w", err)
	}

	// 6. Check all resolved IP addresses
	for _, ip := range ips {
		if isPrivateIP(ip) {
			slog.Warn("SSRF attempt - private IP detected",
				"url", urlStr,
				"hostname", hostname,
				"resolved_ip", ip.String(),
				"security_event", "ssrf_private_ip")
			return fmt.Errorf("access denied: accessing internal network IPs is not allowed (%s)", ip.String())
		}
	}

	return nil
}

// MaxResponseSize returns the maximum response size limit
func (v *HTTP) MaxResponseSize() int64 {
	return v.maxResponseSize
}

// CreateSafeHTTPClient creates an HTTP client with security configuration
func (v *HTTP) CreateSafeHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Limit to maximum 3 redirects
			if len(via) >= 3 {
				slog.Warn("excessive redirects detected",
					"url", req.URL.String(),
					"redirect_count", len(via),
					"security_event", "excessive_redirects")
				return fmt.Errorf("stopped after 3 redirects")
			}

			// Check if the redirect URL is safe
			if err := v.ValidateURL(req.URL.String()); err != nil {
				slog.Warn("SSRF attempt - unsafe redirect detected",
					"redirect_url", req.URL.String(),
					"original_url", via[0].URL.String(),
					"redirect_chain_length", len(via),
					"security_event", "ssrf_unsafe_redirect")
				return fmt.Errorf("redirect to unsafe URL: %w", err)
			}

			return nil
		},
	}
}

// isDangerousHostname checks if it's a dangerous hostname
func isDangerousHostname(hostname string) bool {
	hostname = strings.ToLower(hostname)

	// Local hostnames
	localHostnames := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
	}

	if slices.Contains(localHostnames, hostname) {
		return true
	}

	// Cloud service metadata endpoints
	metadataEndpoints := []string{
		"169.254.169.254", // AWS, Azure, GCP
		"metadata.google.internal",
		"metadata",
	}

	for _, endpoint := range metadataEndpoints {
		if hostname == endpoint || strings.Contains(hostname, endpoint) {
			return true
		}
	}

	return false
}

// isPrivateIP checks if an IP is a private IP address
func isPrivateIP(ip net.IP) bool {
	// IPv4 private ranges
	privateIPv4Ranges := []string{
		"10.0.0.0/8",     // Class A private range
		"172.16.0.0/12",  // Class B private range
		"192.168.0.0/16", // Class C private range
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local (AWS metadata, etc.)
		"0.0.0.0/8",      // Local network
		"224.0.0.0/4",    // Multicast
		"240.0.0.0/4",    // Reserved
	}

	for _, cidr := range privateIPv4Ranges {
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if subnet.Contains(ip) {
			return true
		}
	}

	// IPv6 private address checks
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// IPv6 Unique Local Address (ULA) fc00::/7
	if len(ip) == net.IPv6len && ip[0] == 0xfc || ip[0] == 0xfd {
		return true
	}

	return false
}

// IsURLSafe quickly checks if a URL contains obvious dangerous patterns
// This is an additional layer of protection but should not be relied upon alone
func IsURLSafe(urlStr string) bool {
	urlLower := strings.ToLower(urlStr)

	// Check for dangerous protocols
	dangerousSchemes := []string{
		"file://",
		"ftp://",
		"gopher://",
		"data:",
		"javascript:",
	}

	for _, scheme := range dangerousSchemes {
		if strings.HasPrefix(urlLower, scheme) {
			return false
		}
	}

	// Check for internal IP patterns
	dangerousPatterns := []string{
		"localhost",
		"127.0.0.1",
		"0.0.0.0",
		"169.254.169.254",
		"metadata",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(urlLower, pattern) {
			return false
		}
	}

	return true
}
