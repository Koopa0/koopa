package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{"ref":"refs/heads/main"}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	validSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name    string
		payload []byte
		sig     string
		secret  string
		wantErr bool
	}{
		{
			name:    "valid signature",
			payload: payload,
			sig:     validSig,
			secret:  secret,
		},
		{
			name:    "wrong secret",
			payload: payload,
			sig:     validSig,
			secret:  "wrong-secret",
			wantErr: true,
		},
		{
			name:    "missing sha256 prefix",
			payload: payload,
			sig:     "abc123",
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "invalid hex",
			payload: payload,
			sig:     "sha256=not-hex",
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
			name:    "tampered payload",
			payload: []byte(`{"ref":"refs/heads/evil"}`),
			sig:     validSig,
			secret:  secret,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifySignature(tt.payload, tt.sig, tt.secret)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifySignature() unexpected error: %v", err)
			}
		})
	}
}
