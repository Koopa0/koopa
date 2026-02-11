// Package session provides conversation history persistence with PostgreSQL.
//
// A session represents a conversation context containing ordered messages
// exchanged between user and model. The [Store] handles persistence while
// the agent handles conversation logic.
//
// Key operations:
//
//   - Session lifecycle: [Store.CreateSession], [Store.Session], [Store.Sessions], [Store.DeleteSession], [Store.ResolveCurrentSession]
//   - Message persistence: [Store.AddMessages], [Store.Messages] (transaction-safe batch insertion)
//   - Agent integration: [Store.History], [Store.AppendMessages]
//
// # Transaction Safety
//
// [Store.AddMessages] uses SELECT ... FOR UPDATE to lock the session row,
// preventing race conditions on sequence numbers during concurrent writes.
// If any step fails, the entire transaction rolls back.
//
// # Concurrency
//
// Store is safe for concurrent use. All state lives in PostgreSQL;
// no shared Go-side state exists. Session locking and transaction
// isolation handle concurrent access.
//
// # Local State
//
// [SaveCurrentSessionID] and [LoadCurrentSessionID] persist the active session
// to ~/.koopa/current_session using atomic writes (temp file + rename) with
// file locking via [github.com/gofrs/flock].
package session
