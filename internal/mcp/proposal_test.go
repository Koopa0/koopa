// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

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
				"priority": "medium",
				"content":  "Research NATS exactly-once semantics",
			},
		},
		{
			name:       "hypothesis with claim",
			entityType: "hypothesis",
			fields: map[string]any{
				"claim":                  "Morning practice correlates with better results",
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

// TestProposalFutureIssuedAtRejected pins the expiry lower bound: a token
// whose issued-at is unreasonably in the future must be rejected. ExpiresAt is
// set consistently (iat + TTL) so the existing now>exp upper-bound check passes
// — only an explicit issued-at lower bound can reject this token. Without it a
// future-dated token sails through verification and stays "valid" for its whole
// (future) TTL window.
func TestProposalFutureIssuedAtRejected(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-enough")
	now := time.Now()

	future := proposalPayload{
		Type:      "goal",
		Fields:    map[string]any{"title": "future"},
		IssuedAt:  now.Add(1 * time.Hour).Unix(),
		ExpiresAt: now.Add(1*time.Hour + proposalTTL).Unix(),
		Nonce:     "future-nonce",
	}
	tok, err := encodeToken(secret, future)
	if err != nil {
		t.Fatalf("encodeToken: %v", err)
	}
	if _, err := verifyProposal(secret, tok); err == nil {
		t.Fatal("token with issued-at far in the future should be rejected")
	}

	// A token issued within the allowed clock-skew margin must still verify —
	// the lower bound rejects implausible future timestamps, not ordinary skew.
	skewed := proposalPayload{
		Type:      "goal",
		Fields:    map[string]any{"title": "slight skew"},
		IssuedAt:  now.Add(5 * time.Second).Unix(),
		ExpiresAt: now.Add(5*time.Second + proposalTTL).Unix(),
		Nonce:     "skew-nonce",
	}
	skewTok, err := encodeToken(secret, skewed)
	if err != nil {
		t.Fatalf("encodeToken (skew): %v", err)
	}
	if _, err := verifyProposal(secret, skewTok); err != nil {
		t.Fatalf("token within clock-skew margin should verify, got: %v", err)
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

// TestNonceStore_ConsumeOnceThenReject pins the single-use contract: the first
// consume of a nonce wins, every subsequent consume of the same nonce is
// rejected while the entry is still retained.
func TestNonceStore_ConsumeOnceThenReject(t *testing.T) {
	n := newNonceStore()
	now := time.Now().Unix()
	retain := now + 600

	if !n.consume("nonce-a", retain, now) {
		t.Fatal("first consume of nonce-a should win")
	}
	if n.consume("nonce-a", retain, now) {
		t.Error("second consume of nonce-a should be rejected (replay)")
	}
	// A different nonce is unaffected.
	if !n.consume("nonce-b", retain, now) {
		t.Error("first consume of a distinct nonce-b should win")
	}
	// Once the retention window passes, the nonce is evicted and the SAME
	// nonce value could be claimed again — by then its token is long expired
	// and rejected upstream by verifyProposal, so this is safe.
	if !n.consume("nonce-a", retain, retain+1) {
		t.Error("after retention window, an evicted nonce should be claimable again")
	}
}

// TestNonceStore_ConcurrentConsumeExactlyOne is the TOCTOU-safety guard for the
// nonce claim: when many goroutines race to consume the same nonce, exactly one
// must win. Run with -race to surface any data race in the store itself. This
// is the deterministic, DB-free counterpart to the concurrent integration test.
func TestNonceStore_ConcurrentConsumeExactlyOne(t *testing.T) {
	n := newNonceStore()
	now := time.Now().Unix()
	retain := now + 600

	const goroutines = 64
	var wins atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range goroutines {
		wg.Go(func() {
			<-start
			if n.consume("contended-nonce", retain, now) {
				wins.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()

	if got := wins.Load(); got != 1 {
		t.Errorf("concurrent consume winners = %d, want exactly 1", got)
	}
}

func flipByte(s string, idx int) string {
	b := []byte(s)
	if idx < len(b) {
		b[idx] ^= 0xFF
	}
	return string(b)
}
