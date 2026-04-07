package mcp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// proposalTTL is how long a proposal token remains valid.
const proposalTTL = 10 * time.Minute

// proposalPayload is the signed data inside a proposal token.
type proposalPayload struct {
	Type      string         `json:"type"`
	Fields    map[string]any `json:"fields"`
	IssuedAt  int64          `json:"iat"`
	ExpiresAt int64          `json:"exp"`
	Nonce     string         `json:"nonce"`
}

// signProposal creates an HMAC-signed proposal token.
// The token is base64(json(payload) + "." + hmac-sha256(json(payload))).
func signProposal(secret []byte, entityType string, fields map[string]any) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	now := time.Now()
	payload := proposalPayload{
		Type:      entityType,
		Fields:    fields,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(proposalTTL).Unix(),
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling proposal: %w", err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	sig := mac.Sum(nil)

	// Token format: base64url(payload) + "." + base64url(signature)
	token := base64.RawURLEncoding.EncodeToString(data) +
		"." +
		base64.RawURLEncoding.EncodeToString(sig)

	return token, nil
}

// verifyProposal verifies and decodes a proposal token.
// Returns the payload if valid, or an error if expired/tampered.
func verifyProposal(secret []byte, token string) (*proposalPayload, error) {
	// Split token into payload and signature.
	dot := -1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return nil, fmt.Errorf("invalid proposal token format")
	}

	payloadB64 := token[:dot]
	sigB64 := token[dot+1:]

	data, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("decoding proposal payload: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("decoding proposal signature: %w", err)
	}

	// Verify HMAC.
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return nil, fmt.Errorf("proposal token signature invalid")
	}

	// Decode payload.
	var payload proposalPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("decoding proposal payload: %w", err)
	}

	// Check expiry.
	if time.Now().Unix() > payload.ExpiresAt {
		return nil, fmt.Errorf("proposal token expired (issued %s, TTL %s)",
			time.Unix(payload.IssuedAt, 0).Format(time.RFC3339), proposalTTL)
	}

	return &payload, nil
}
