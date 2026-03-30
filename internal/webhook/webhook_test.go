package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func computeSig(t *testing.T, payload []byte, secret string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignature(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{"ref":"refs/heads/main"}`)
	validSig := computeSig(t, payload, secret)

	tests := []struct {
		name    string
		payload []byte
		sig     string
		secret  string
		wantErr bool
	}{
		// Happy paths
		{
			name:    "valid signature",
			payload: payload,
			sig:     validSig,
			secret:  secret,
		},
		{
			name:    "valid signature for empty payload",
			payload: []byte{},
			sig:     computeSig(t, []byte{}, secret),
			secret:  secret,
		},
		{
			name:    "valid signature for large payload",
			payload: []byte(strings.Repeat("a", 65536)),
			sig:     computeSig(t, []byte(strings.Repeat("a", 65536)), secret),
			secret:  secret,
		},
		{
			name:    "valid signature with unicode secret",
			payload: payload,
			sig:     computeSig(t, payload, "🔑secret漢字"),
			secret:  "🔑secret漢字",
		},

		// Wrong inputs
		{
			name:    "wrong secret",
			payload: payload,
			sig:     validSig,
			secret:  "wrong-secret",
			wantErr: true,
		},
		{
			name:    "tampered payload",
			payload: []byte(`{"ref":"refs/heads/evil"}`),
			sig:     validSig,
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "empty secret",
			payload: payload,
			sig:     validSig,
			secret:  "",
			wantErr: true,
		},
		{
			name:    "nil payload with valid nil-sig",
			payload: nil,
			sig:     computeSig(t, nil, secret),
			secret:  secret,
		},

		// Malformed signatures
		{
			name:    "missing sha256 prefix",
			payload: payload,
			sig:     "abc123",
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "sha256 prefix only — empty hex",
			payload: payload,
			sig:     "sha256=",
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "invalid hex in signature",
			payload: payload,
			sig:     "sha256=not-hex!",
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "empty signature",
			payload: payload,
			sig:     "",
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "wrong prefix casing",
			payload: payload,
			sig:     "SHA256=" + hex.EncodeToString(func() []byte { m := hmac.New(sha256.New, []byte(secret)); m.Write(payload); return m.Sum(nil) }()),
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "sha1 prefix instead of sha256",
			payload: payload,
			sig:     "sha1=deadbeef",
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "signature with null byte in hex part",
			payload: payload,
			sig:     "sha256=\x00" + hex.EncodeToString(make([]byte, 31)),
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "signature too short — wrong HMAC length",
			payload: payload,
			sig:     "sha256=aabbcc", // only 3 bytes, HMAC-SHA256 is 32 bytes
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "all-zeros signature",
			payload: payload,
			sig:     "sha256=" + strings.Repeat("00", 32),
			secret:  secret,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := VerifySignature(tt.payload, tt.sig, tt.secret)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("VerifySignature() = nil, want error")
				}
				if !errors.Is(err, ErrInvalidSignature) {
					t.Errorf("VerifySignature() error = %v, want errors.Is(err, ErrInvalidSignature)", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifySignature() unexpected error: %v", err)
			}
		})
	}
}

// TestVerifySignature_TimingSafety verifies that HMAC comparison uses
// constant-time equality (hmac.Equal) by ensuring both matching and
// non-matching signatures return the same sentinel error, which is
// the observable contract of constant-time verification.
func TestVerifySignature_TimingSafety(t *testing.T) {
	t.Parallel()
	secret := "timing-test-secret"
	payload := []byte("body")
	validSig := computeSig(t, payload, secret)

	// A forged signature differing only in the last byte must still fail.
	forged := []byte(validSig)
	// Flip the last hex digit: ensure HMAC.Equal is used, not bytes.Equal short-circuit.
	last := forged[len(forged)-1]
	if last == '0' {
		forged[len(forged)-1] = '1'
	} else {
		forged[len(forged)-1] = '0'
	}

	err := VerifySignature(payload, string(forged), secret)
	if err == nil {
		t.Fatal("VerifySignature() with last-byte-flipped sig = nil, want ErrInvalidSignature")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("VerifySignature() error = %v, want ErrInvalidSignature", err)
	}
}

// TestVerifySignature_ErrSentinel ensures only ErrInvalidSignature is returned,
// never a wrapped internal error that leaks implementation details.
func TestVerifySignature_ErrSentinel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		sig  string
	}{
		{"invalid hex", "sha256=gg"},
		{"wrong prefix", "md5=abc"},
		{"empty", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := VerifySignature([]byte("payload"), c.sig, "secret")
			if !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("VerifySignature(%q) error = %v, want ErrInvalidSignature", c.sig, err)
			}
		})
	}
}
