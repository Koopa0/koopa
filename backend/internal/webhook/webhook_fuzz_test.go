package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// FuzzVerifySignature ensures VerifySignature never panics on arbitrary input.
// The function must either return nil (valid) or ErrInvalidSignature — never crash.
func FuzzVerifySignature(f *testing.F) {
	// Seed: valid cases
	secret := "test-secret"
	payload := []byte(`{"ref":"refs/heads/main"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	validSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	f.Add(payload, validSig, secret)
	f.Add(payload, "", secret)
	f.Add(payload, "sha256=", secret)
	f.Add(payload, "sha256=gg", secret)
	f.Add(payload, "sha256="+hex.EncodeToString(make([]byte, 32)), "")
	f.Add([]byte{}, validSig, secret)
	f.Add([]byte{0x00}, "sha256=\x00", "")
	f.Add([]byte("payload"), "SHA256=abc", "secret")

	f.Fuzz(func(t *testing.T, payload []byte, signature, secret string) {
		// Must not panic. Return value is either nil or ErrInvalidSignature.
		_ = VerifySignature(payload, signature, secret)
	})
}

// FuzzValidateTimestamp ensures ValidateTimestamp never panics on arbitrary input.
func FuzzValidateTimestamp(f *testing.F) {
	f.Add("2024-01-01T00:00:00Z")
	f.Add("")
	f.Add("not-a-date")
	f.Add("2024-01-01")
	f.Add("9999-12-31T23:59:59Z")
	f.Add("1970-01-01T00:00:00Z")
	f.Add("2024-06-15T10:00:00.999Z")
	f.Add("2024-06-15T10:00:00+09:00")
	f.Add("\x00\x01\x02")

	f.Fuzz(func(t *testing.T, ts string) {
		// Must not panic. Return value is either nil or a non-nil error.
		_ = ValidateTimestamp(ts, 0)
	})
}
