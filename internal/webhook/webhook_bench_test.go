package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func BenchmarkVerifySignature_Valid(b *testing.B) {
	b.ReportAllocs()
	secret := "bench-secret"
	payload := []byte(`{"ref":"refs/heads/main","after":"abc123"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	b.ResetTimer()
	for b.Loop() {
		_ = VerifySignature(payload, sig, secret)
	}
}

func BenchmarkVerifySignature_Invalid(b *testing.B) {
	b.ReportAllocs()
	secret := "bench-secret"
	payload := []byte(`{"ref":"refs/heads/main"}`)
	sig := "sha256=" + hex.EncodeToString(make([]byte, 32)) // wrong HMAC

	b.ResetTimer()
	for b.Loop() {
		_ = VerifySignature(payload, sig, secret)
	}
}

func BenchmarkVerifySignature_LargePayload(b *testing.B) {
	b.ReportAllocs()
	secret := "bench-secret"
	payload := make([]byte, 64*1024) // 64 KB
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	b.ResetTimer()
	for b.Loop() {
		_ = VerifySignature(payload, sig, secret)
	}
}

func BenchmarkDeduplicationCache_Seen_Miss(b *testing.B) {
	b.ReportAllocs()
	c := NewDeduplicationCache(10 * time.Minute)
	defer c.Stop()

	b.ResetTimer()
	for b.Loop() {
		// Each iteration uses a counter-based key to ensure a cache miss.
		c.Seen("bench-miss-key-that-wont-repeat")
	}
}

func BenchmarkDeduplicationCache_Seen_Hit(b *testing.B) {
	b.ReportAllocs()
	c := NewDeduplicationCache(10 * time.Minute)
	defer c.Stop()

	const key = "bench-hit-key"
	c.Seen(key) // prime the cache

	b.ResetTimer()
	for b.Loop() {
		c.Seen(key)
	}
}

func BenchmarkValidateTimestamp(b *testing.B) {
	b.ReportAllocs()
	ts := time.Now().UTC().Format(time.RFC3339)
	maxSkew := 5 * time.Minute

	b.ResetTimer()
	for b.Loop() {
		_ = ValidateTimestamp(ts, maxSkew)
	}
}

func BenchmarkValidateTimestamp_Invalid(b *testing.B) {
	b.ReportAllocs()
	ts := "not-a-timestamp"
	maxSkew := 5 * time.Minute

	b.ResetTimer()
	for b.Loop() {
		_ = ValidateTimestamp(ts, maxSkew)
	}
}
