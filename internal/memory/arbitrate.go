package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// maxArbitrationResponseBytes limits arbitration LLM response size (5 KB).
const maxArbitrationResponseBytes = 5 * 1024

// arbitrationPrompt instructs the LLM to resolve a memory conflict.
// Nonce-delimited boundaries prevent prompt injection from memory content.
// %s placeholders: (1) nonce, (2) existing, (3) nonce, (4) nonce, (5) candidate, (6) nonce.
const arbitrationPrompt = `You are a memory conflict resolver. Given an EXISTING memory and a NEW candidate fact about the same user, decide the correct action.

===EXISTING_%s===
%s
===END_EXISTING_%s===

===CANDIDATE_%s===
%s
===END_CANDIDATE_%s===

Decide one action:
- ADD: Both facts are distinct and should coexist
- UPDATE: The new fact is an evolution of the existing one. Provide merged content in "content".
- DELETE: The new fact completely invalidates the existing one
- NOOP: The new fact is effectively a duplicate. Discard it.

Output JSON only: {"operation": "...", "content": "...", "reasoning": "..."}`

// Arbitrate asks the LLM to resolve a conflict between an existing memory
// and a new candidate fact. Called when cosine similarity is in [0.85, 0.95).
func Arbitrate(ctx context.Context, g *genkit.Genkit, modelName string,
	existing, candidate string) (*ArbitrationResult, error) {

	nonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Sanitize content to prevent delimiter injection (defense-in-depth).
	prompt := fmt.Sprintf(arbitrationPrompt, nonce, sanitizeDelimiters(existing), nonce, nonce, sanitizeDelimiters(candidate), nonce)

	opts := []ai.GenerateOption{
		ai.WithPrompt(prompt),
	}
	if modelName != "" {
		opts = append(opts, ai.WithModelName(modelName))
	}

	resp, err := genkit.Generate(ctx, g, opts...)
	if err != nil {
		return nil, fmt.Errorf("generating arbitration: %w", err)
	}

	raw := resp.Text()
	if len(raw) > maxArbitrationResponseBytes {
		return nil, fmt.Errorf("arbitration response too large: %d bytes", len(raw))
	}

	text := strings.TrimSpace(raw)
	if text == "" {
		return nil, fmt.Errorf("empty arbitration response")
	}

	text = stripCodeFences(text)

	var result ArbitrationResult
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		return nil, fmt.Errorf("parsing arbitration result: %w (raw: %q)", err, truncate(text, 200))
	}

	if !validOperation(result.Operation) {
		return nil, fmt.Errorf("invalid arbitration operation: %q", result.Operation)
	}

	return &result, nil
}

// validOperation checks if op is one of the known operations.
func validOperation(op Operation) bool {
	switch op {
	case OpAdd, OpUpdate, OpDelete, OpNoop:
		return true
	}
	return false
}
