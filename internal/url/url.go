// Package url provides a canonical form for external URLs and its SHA-256
// hash, used as dedup identity across tables that store external URLs
// (feed_entries.url_hash and bookmarks.url_hash). A single authoritative
// canonicalisation is required because both tables share UNIQUE(url_hash) —
// if the RSS collector and the bookmark handler disagree on the canonical
// form, the same URL from two ingress points hashes differently and dedup
// fails.
//
// This package shadows stdlib net/url by package name. Callers that need
// both must alias one import:
//
//	import (
//	    neturl "net/url"
//	    "github.com/Koopa0/koopa/internal/url"
//	)
//
// Canonicalisation rules (applied in order):
//
//  1. Lowercase the scheme and host. "HTTP://EXAMPLE.com/x" and
//     "http://example.com/x" must dedup.
//  2. Strip default ports (:80 for http, :443 for https).
//  3. Remove trailing slash from the path, preserving the root "/".
//  4. Remove the fragment entirely (#section-2). Fragments never denote
//     distinct resources for dedup purposes on this codebase.
//  5. Drop known tracking query parameters (utm_*, fbclid, gclid, etc.).
//     The denylist is explicit and versioned — see TrackingParamDenylist.
//  6. Sort remaining query parameters alphabetically.
//  7. Normalize percent-encoding hex to uppercase.
//
// Punycode normalisation for internationalized domain names is NOT applied —
// IDN hosts are rare in this codebase's use case (technical articles in
// English / CJK ASCII-friendly domains). Reintroduce if IDN duplication
// becomes a concrete problem.
package url

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	neturl "net/url"
	"sort"
	"strings"
)

// TrackingParamDenylist lists query parameters stripped during canonicalisation.
// The list is explicit and versioned rather than pattern-based to keep the
// canonical form auditable. Add a param by extending this slice and bumping
// any dependent tests.
var TrackingParamDenylist = []string{
	"utm_source",
	"utm_medium",
	"utm_campaign",
	"utm_term",
	"utm_content",
	"fbclid",
	"gclid",
	"msclkid",
	"mc_cid",
	"mc_eid",
	"_ga",
	"_gac",
	"ref",
	"ref_src",
	"source",
}

// ErrInvalidURL signals that the input could not be parsed as a URL.
var ErrInvalidURL = fmt.Errorf("url: invalid URL")

// Canonical returns the canonical string form of rawURL per the rules in the
// package doc. It returns ErrInvalidURL if rawURL fails parsing, or if the
// parsed URL has no host (relative URLs aren't canonicalisable for dedup).
func Canonical(rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidURL)
	}

	u, err := neturl.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%w: missing host", ErrInvalidURL)
	}

	// 1. Lowercase scheme and host.
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// 2. Strip default ports.
	host, port := splitHostPort(u.Host)
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		u.Host = host
	}

	// 3. Strip trailing slash from path, keeping root "/".
	if len(u.Path) > 1 && strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimRight(u.Path, "/")
	}

	// 4. Drop fragment.
	u.Fragment = ""
	u.RawFragment = ""

	// 5 + 6. Filter tracking params, then sort remaining alphabetically.
	if u.RawQuery != "" {
		q := u.Query()
		for _, deny := range TrackingParamDenylist {
			q.Del(deny)
		}
		u.RawQuery = sortedEncode(q)
	}

	// 7. Percent-encoding hex normalization to uppercase.
	return normalizeHexEscapes(u.String()), nil
}

// Hash returns the SHA-256 hex digest of the canonical form of rawURL.
// Returns ErrInvalidURL if canonicalisation fails.
func Hash(rawURL string) (string, error) {
	canonical, err := Canonical(rawURL)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}

// splitHostPort splits host:port, returning ("host", "port") or ("host", "") if
// no port is present. Unlike net.SplitHostPort, this tolerates a missing port.
func splitHostPort(hostport string) (host, port string) {
	// IPv6 bracketed literal: [::1]:8080
	if strings.HasPrefix(hostport, "[") {
		if idx := strings.LastIndex(hostport, "]"); idx != -1 {
			host = hostport[:idx+1]
			if idx+1 < len(hostport) && hostport[idx+1] == ':' {
				port = hostport[idx+2:]
			}
			return host, port
		}
	}
	if idx := strings.LastIndex(hostport, ":"); idx != -1 {
		return hostport[:idx], hostport[idx+1:]
	}
	return hostport, ""
}

// sortedEncode returns the URL-encoded form of v with keys in alphabetical
// order and, for each key, values in insertion order. Differs from
// neturl.Values.Encode which only sorts keys.
func sortedEncode(v neturl.Values) string {
	if len(v) == 0 {
		return ""
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf strings.Builder
	for i, k := range keys {
		for _, val := range v[k] {
			if buf.Len() > 0 || i > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(neturl.QueryEscape(k))
			buf.WriteByte('=')
			buf.WriteString(neturl.QueryEscape(val))
		}
	}
	return buf.String()
}

// normalizeHexEscapes uppercases the two hex characters following every '%'
// in s. Does not decode or re-encode anything else — preserves the exact
// byte sequence produced by URL.String() other than hex case.
func normalizeHexEscapes(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			buf.WriteByte('%')
			buf.WriteByte(upperHex(s[i+1]))
			buf.WriteByte(upperHex(s[i+2]))
			i += 2
			continue
		}
		buf.WriteByte(s[i])
	}
	return buf.String()
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func upperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}
