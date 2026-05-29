// proposal.go implements the HMAC-signed proposal token used by the
// two-phase commit pattern (propose_<type> → commit_proposal).
//
// A proposal token is base64(payload).base64(hmac-sha256(payload)).
// Key properties:
//
//   - The HMAC secret is generated fresh in NewServer. Proposals do NOT
//     survive a server restart — that is deliberate, proposals are not
//     long-lived commitments.
//   - TTL is 10 minutes. An expired token is a hard reject; the client
//     must re-propose. A token whose issued-at is implausibly in the future
//     (beyond a small clock-skew margin) is likewise rejected.
//   - Nonce prevents replay within the TTL window: commit_proposal consumes
//     the nonce via nonceStore, so a valid token commits at most once. The
//     consume is atomic, so concurrent commits of the same token cannot both
//     succeed. The store lives in-process only, which is sufficient because
//     the HMAC secret regenerates on restart — a token from a previous
//     instance fails signature verification before the nonce is ever checked.
//
// Do NOT persist tokens. If a caller needs to "remember" a proposal,
// that is a product signal that the two-phase pattern is wrong for
// that workflow — add a direct write tool instead.

package mcp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// proposalTTL is how long a proposal token remains valid.
const proposalTTL = 10 * time.Minute

// proposalClockSkew bounds how far in the future a token's issued-at may be
// before it is rejected. Tokens are minted and verified by the same process
// (the HMAC secret is per-instance), so legitimate skew is near zero; this
// margin only absorbs coarse clock granularity. A token claiming to be issued
// further ahead than this is implausible and rejected.
const proposalClockSkew = 60 * time.Second

// proposalNonceRetention is how long a consumed nonce is retained beyond the
// token's expiry before it may be evicted. Slightly longer than the token TTL
// so a replay anywhere inside the token's validity window always finds the
// consumed nonce; once the token itself is expired (rejected by the expiry
// check) the nonce no longer needs remembering.
const proposalNonceRetention = 60 * time.Second

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

	return encodeToken(secret, payload)
}

// encodeToken HMAC-signs a payload and returns the token string.
func encodeToken(secret []byte, payload proposalPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling proposal: %w", err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	sig := mac.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(data) +
		"." +
		base64.RawURLEncoding.EncodeToString(sig), nil
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
		return nil, fmt.Errorf("proposal token signature mismatch — token may have been tampered with or issued by a previous server instance (HMAC secret regenerates on restart)")
	}

	// Decode payload.
	var payload proposalPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("decoding proposal payload: %w", err)
	}

	now := time.Now()

	// Reject an implausible future issued-at. The upper-bound expiry check
	// below cannot catch this: a future-dated token also carries a
	// future-dated ExpiresAt, so now>exp is false and it would otherwise sail
	// through and stay "valid" for its whole future TTL window.
	if payload.IssuedAt > now.Add(proposalClockSkew).Unix() {
		return nil, fmt.Errorf("proposal token issued in the future at %s (now %s, max skew %s) — rejected",
			time.Unix(payload.IssuedAt, 0).Format(time.RFC3339),
			now.Format(time.RFC3339), proposalClockSkew)
	}

	// Check expiry.
	if now.Unix() > payload.ExpiresAt {
		return nil, fmt.Errorf("proposal token expired at %s (issued %s, TTL %s) — re-propose to get a new token",
			time.Unix(payload.ExpiresAt, 0).Format(time.RFC3339),
			time.Unix(payload.IssuedAt, 0).Format(time.RFC3339), proposalTTL)
	}

	return &payload, nil
}

// nonceStore records the nonces of proposal tokens that have already been
// committed, so a valid token cannot be replayed within its TTL window. It is
// the mechanism-layer replay defense: one store guards every proposal type, so
// goal / project / milestone / hypothesis / learning_plan / learning_domain /
// directive are all covered by the single consume gate in commitProposal.
//
// Entries are kept in memory only. That is sufficient — and correct — because
// the proposal HMAC secret is regenerated per process (see NewServer): a token
// minted by a previous instance fails signature verification, so it never
// reaches the nonce check. The store therefore only needs to remember a nonce
// for as long as its token is verifiable, i.e. within this process.
type nonceStore struct {
	mu   sync.Mutex
	seen map[string]int64 // nonce → unix time after which the entry may be evicted
}

func newNonceStore() *nonceStore {
	return &nonceStore{seen: make(map[string]int64)}
}

// consume atomically claims nonce. It returns true when the nonce was not
// previously claimed (the caller may proceed to commit) and false when it was
// already claimed (a replay — the caller must reject). retainUntil is the unix
// time the entry may be evicted; now is the current unix time.
//
// The presence check and the claim happen under a single lock hold, so there
// is no check-then-act window: two concurrent callers with the same nonce
// cannot both receive true. Exactly one wins the claim.
func (n *nonceStore) consume(nonce string, retainUntil, now int64) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Lazy eviction: drop entries whose retention window has passed. Commits
	// are human-gated and infrequent, so an O(n) sweep per call is cheap and
	// keeps the map bounded over a long-lived process.
	for k, exp := range n.seen {
		if now > exp {
			delete(n.seen, k)
		}
	}

	if _, claimed := n.seen[nonce]; claimed {
		return false
	}
	n.seen[nonce] = retainUntil
	return true
}
