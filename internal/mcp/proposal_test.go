package mcp

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

//nolint:gocognit // test complexity is acceptable for comprehensive table-driven tests
func TestProposalRoundTrip(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-enough")

	tests := []struct {
		name       string
		entityType string
		fields     map[string]any
	}{
		{
			name:       "goal with all fields",
			entityType: "goal",
			fields: map[string]any{
				"title":       "JLPT N2 by June",
				"description": "Pass JLPT N2 exam",
				"area_id":     "550e8400-e29b-41d4-a716-446655440000",
				"quarter":     "2026-Q2",
				"deadline":    "2026-06-30",
			},
		},
		{
			name:       "directive minimal",
			entityType: "directive",
			fields: map[string]any{
				"source":   "hq",
				"target":   "research-lab",
				"priority": "p1",
				"content":  "Research NATS exactly-once semantics",
			},
		},
		{
			name:       "insight with hypothesis",
			entityType: "insight",
			fields: map[string]any{
				"hypothesis":             "Morning practice correlates with better results",
				"invalidation_condition": "Evening sessions show equal solve rates over 30 days",
				"content":                "Observed pattern across 2 weeks",
			},
		},
		{
			name:       "empty fields",
			entityType: "goal",
			fields:     map[string]any{},
		},
		{
			name:       "special characters",
			entityType: "milestone",
			fields: map[string]any{
				"title":   `Goal with "quotes" & <brackets> and 中文`,
				"goal_id": "550e8400-e29b-41d4-a716-446655440000",
			},
		},
		{
			name:       "nested metadata",
			entityType: "directive",
			fields: map[string]any{
				"source":  "hq",
				"target":  "content-studio",
				"content": "Write article",
				"metadata": map[string]any{
					// JSON round-trip converts []string → []any — this is expected
					// json.Unmarshal behavior for map[string]any targets.
					"tags":     []any{"go", "generics"},
					"deadline": "2026-04-15",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := signProposal(secret, tt.entityType, tt.fields)
			if err != nil {
				t.Fatalf("signProposal: %v", err)
			}
			if token == "" {
				t.Fatal("empty token")
			}

			payload, err := verifyProposal(secret, token)
			if err != nil {
				t.Fatalf("verifyProposal: %v", err)
			}

			if payload.Type != tt.entityType {
				t.Errorf("type: got %q, want %q", payload.Type, tt.entityType)
			}
			if diff := cmp.Diff(tt.fields, payload.Fields); diff != "" {
				t.Errorf("fields mismatch (-want +got):\n%s", diff)
			}
			if payload.Nonce == "" {
				t.Error("nonce is empty")
			}
			if payload.ExpiresAt <= payload.IssuedAt {
				t.Error("ExpiresAt should be after IssuedAt")
			}
		})
	}
}

func TestProposalExpiry(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-enough")

	// Fresh token should be valid.
	token, signErr := signProposal(secret, "goal", map[string]any{"title": "test"})
	if signErr != nil {
		t.Fatalf("signProposal: %v", signErr)
	}
	if _, verifyErr := verifyProposal(secret, token); verifyErr != nil {
		t.Fatalf("fresh token rejected: %v", verifyErr)
	}

	// Manually create expired token using encodeToken.
	expired := proposalPayload{
		Type:      "goal",
		Fields:    map[string]any{"title": "test"},
		IssuedAt:  time.Now().Add(-20 * time.Minute).Unix(),
		ExpiresAt: time.Now().Add(-10 * time.Minute).Unix(),
		Nonce:     "expired-nonce",
	}
	expiredToken, err := encodeToken(secret, expired)
	if err != nil {
		t.Fatalf("encodeToken: %v", err)
	}
	if _, err := verifyProposal(secret, expiredToken); err == nil {
		t.Fatal("expired token should be rejected")
	}
}

func TestProposalTamper(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-enough")

	token, err := signProposal(secret, "goal", map[string]any{"title": "test"})
	if err != nil {
		t.Fatalf("signProposal: %v", err)
	}

	tests := []struct {
		name  string
		token string
	}{
		{"flipped byte", flipByte(token, 5)},
		{"wrong secret verified", ""},
		{"no dot separator", "nodot"},
		{"empty", ""},
		{"only dot", "."},
		{"double dot", "abc.def.ghi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := tt.token
			if tt.name == "wrong secret verified" {
				// Sign with correct secret, verify with wrong.
				wrongSecret := []byte("wrong-secret-32-bytes-long-enuf!")
				if _, err := verifyProposal(wrongSecret, token); err == nil {
					t.Fatal("wrong secret should be rejected")
				}
				return
			}
			if _, err := verifyProposal(secret, tok); err == nil {
				t.Fatalf("tampered token %q should be rejected", tt.name)
			}
		})
	}
}

func flipByte(s string, idx int) string {
	b := []byte(s)
	if idx < len(b) {
		b[idx] ^= 0xFF
	}
	return string(b)
}
