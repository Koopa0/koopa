package tools

import (
	"context"
)

// ownerIDKey is an unexported context key for zero-allocation type safety.
type ownerIDKey struct{}

// OwnerIDFromContext retrieves the owner identity from context.
// Returns empty string if not set.
// Used by knowledge tools to tag and filter documents by owner.
func OwnerIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(ownerIDKey{}).(string)
	return id
}

// ContextWithOwnerID stores the owner identity in context.
// The API layer injects the authenticated user ID; knowledge tools read it
// for per-user document isolation (RAG poisoning prevention).
func ContextWithOwnerID(ctx context.Context, ownerID string) context.Context {
	return context.WithValue(ctx, ownerIDKey{}, ownerID)
}
