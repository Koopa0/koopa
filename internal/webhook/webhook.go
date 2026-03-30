// Package webhook provides shared HMAC-SHA256 signature verification for webhooks.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// ErrInvalidSignature is returned when the webhook signature does not match.
var ErrInvalidSignature = errors.New("invalid signature")

// VerifySignature verifies an HMAC-SHA256 signature in "sha256=<hex>" format.
// Both GitHub (X-Hub-Signature-256) and Notion (X-Notion-Signature) use this format.
func VerifySignature(payload []byte, signature, secret string) error {
	if !strings.HasPrefix(signature, "sha256=") {
		return ErrInvalidSignature
	}

	sigHex := strings.TrimPrefix(signature, "sha256=")
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return ErrInvalidSignature
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := mac.Sum(nil)

	if !hmac.Equal(sigBytes, expected) {
		return ErrInvalidSignature
	}

	return nil
}
