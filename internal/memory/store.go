package memory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pgvector/pgvector-go"
	"google.golang.org/genai"
)

// querier is the common interface satisfied by both *pgxpool.Pool and pgx.Tx.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// memoryCols is the standard SELECT column list for scanMemories.
const memoryCols = `id, owner_id, content, category, source_session_id,
	active, created_at, updated_at,
	importance, access_count, last_accessed_at,
	decay_score, superseded_by, expires_at`

// insertMemorySQL is the standard INSERT used across dedup paths.
// Uses ON CONFLICT to handle exact content duplicates idempotently.
const insertMemorySQL = `INSERT INTO memories (owner_id, content, embedding, category, source_session_id, expires_at, importance)
	VALUES ($1, $2, $3, $4, $5, $6, $7)
	ON CONFLICT (owner_id, md5(content)) WHERE active = true DO NOTHING`

// Store manages persistent memory backed by PostgreSQL + pgvector.
//
// Store is safe for concurrent use by multiple goroutines.
type Store struct {
	pool     *pgxpool.Pool
	embedder ai.Embedder
	logger   *slog.Logger
}

// NewStore creates a memory Store.
func NewStore(pool *pgxpool.Pool, embedder ai.Embedder, logger *slog.Logger) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("pool is required")
	}
	if embedder == nil {
		return nil, fmt.Errorf("embedder is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{pool: pool, embedder: embedder, logger: logger}, nil
}

// embed generates a vector embedding for the given text.
func (s *Store) embed(ctx context.Context, text string) (pgvector.Vector, error) {
	dim := VectorDimension
	resp, err := s.embedder.Embed(ctx, &ai.EmbedRequest{
		Input:   []*ai.Document{ai.DocumentFromText(text, nil)},
		Options: &genai.EmbedContentConfig{OutputDimensionality: &dim},
	})
	if err != nil {
		return pgvector.Vector{}, fmt.Errorf("embedding text: %w", err)
	}
	if len(resp.Embeddings) == 0 || len(resp.Embeddings[0].Embedding) == 0 {
		return pgvector.Vector{}, fmt.Errorf("empty embedding response")
	}
	return pgvector.NewVector(resp.Embeddings[0].Embedding), nil
}

// Add inserts a new memory or updates an existing near-duplicate.
//
// Add is not a pure CREATE — it includes dedup check, merge, arbitration,
// and potential reactivation of soft-deleted duplicates.
//
// Two-threshold dedup algorithm:
//  1. Validate inputs, embed content (outside transaction)
//  2. Begin transaction with per-owner advisory lock
//  3. Find nearest neighbor across all memories (active + inactive) for the owner
//  4. Similarity >= 0.95 (AutoMerge): UPDATE existing in-place
//  5. Similarity in [0.85, 0.95) (Arbitration): call arb.Arbitrate() if non-nil
//     - ADD: insert new row
//     - UPDATE: update existing with merged content
//     - DELETE: soft-delete existing, insert new
//     - NOOP: discard candidate
//  6. Similarity < 0.85: always INSERT new row
//  7. Commit, then evict if over cap (best-effort)
//
// The transaction + advisory lock prevents TOCTOU races where concurrent
// Add() calls for the same owner could find the same nearest neighbor and
// produce a lost update.
//
// NOTE: The arbitration LLM call and OpUpdate re-embedding happen inside
// the transaction. This is acceptable because the advisory lock is per-owner
// (not global) and memory extraction is a low-throughput background operation.
func (s *Store) Add(ctx context.Context, content string, category Category,
	ownerID string, sessionID uuid.UUID, opts AddOpts, arb Arbitrator) error {
	if err := validateAddInput(content, category, ownerID); err != nil {
		return err
	}

	importance := resolveImportance(opts.Importance)
	expiresAt := s.resolveExpiry(opts.ExpiresIn, category)

	// Embed with timeout (outside transaction — no DB connection held).
	embedCtx, cancel := context.WithTimeout(ctx, EmbedTimeout)
	defer cancel()

	vec, err := s.embed(embedCtx, content)
	if err != nil {
		return fmt.Errorf("embedding: %w", err)
	}

	// Begin transaction for atomic dedup.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
			s.logger.Debug("transaction rollback", "error", rbErr)
		}
	}()

	// Serialize concurrent Add() calls for the same owner.
	// pg_advisory_xact_lock releases automatically at commit/rollback.
	if _, lockErr := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, ownerID); lockErr != nil {
		return fmt.Errorf("acquiring advisory lock: %w", lockErr)
	}

	// Find nearest neighbor within the transaction (consistent read).
	nearest, similarity, found, err := s.findNearest(ctx, tx, vec, ownerID)
	if err != nil {
		return err
	}

	if found {
		if err := s.addWithDedup(ctx, tx, nearest, similarity, content, vec, category, ownerID, sessionID, expiresAt, importance, arb); err != nil {
			return err
		}
	} else {
		if err := s.insertRow(ctx, tx, content, vec, category, ownerID, sessionID, expiresAt, importance); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing memory transaction: %w", err)
	}

	// Evict outside the transaction (best-effort, does not need the lock).
	if evictErr := s.evictIfNeeded(ctx, ownerID); evictErr != nil {
		s.logger.Warn("eviction failed", "error", evictErr)
	}

	return nil
}

// validateAddInput checks required fields for Add().
func validateAddInput(content string, category Category, ownerID string) error {
	if !category.Valid() {
		return fmt.Errorf("invalid category: %q", category)
	}
	if content == "" {
		return fmt.Errorf("content is required")
	}
	if len(content) > MaxContentLength {
		return fmt.Errorf("content length %d exceeds maximum %d", len(content), MaxContentLength)
	}
	if ownerID == "" {
		return fmt.Errorf("owner ID is required")
	}
	if ContainsSecrets(content) {
		return fmt.Errorf("content contains potential secrets")
	}
	return nil
}

// resolveImportance clamps importance to 1-10 (default 5).
func resolveImportance(v int) int {
	if v >= 1 && v <= 10 {
		return v
	}
	return 5
}

// resolveExpiry resolves the expiration timestamp from AddOpts or category default.
func (s *Store) resolveExpiry(expiresIn string, category Category) *time.Time {
	if expiresIn == "" {
		return category.ExpiresAt()
	}
	d, err := parseExpiresIn(expiresIn)
	if err != nil {
		s.logger.Warn("invalid expires_in, using category default", "expires_in", expiresIn, "error", err)
		return category.ExpiresAt()
	}
	if d == 0 {
		return nil // never expires
	}
	t := time.Now().Add(d)
	return &t
}

// nearestNeighbor holds the result of a nearest-neighbor lookup.
type nearestNeighbor struct {
	id      uuid.UUID
	active  bool
	content string
}

// findNearest finds the nearest neighbor for dedup. Returns found=false if no neighbors exist.
func (*Store) findNearest(ctx context.Context, q querier, vec pgvector.Vector, ownerID string) (nn nearestNeighbor, similarity float64, found bool, err error) {
	queryErr := q.QueryRow(ctx,
		`SELECT id, active, content, 1 - (embedding <=> $1) AS similarity
		 FROM memories
		 WHERE owner_id = $2
		 ORDER BY embedding <=> $1
		 LIMIT 1`,
		vec, ownerID,
	).Scan(&nn.id, &nn.active, &nn.content, &similarity)

	switch {
	case errors.Is(queryErr, pgx.ErrNoRows):
		return nearestNeighbor{}, 0, false, nil
	case queryErr != nil:
		return nearestNeighbor{}, 0, false, fmt.Errorf("querying nearest neighbor: %w", queryErr)
	default:
		return nn, similarity, true, nil
	}
}

// addWithDedup applies two-threshold dedup logic when a nearest neighbor was found.
func (s *Store) addWithDedup(ctx context.Context, q querier, nn nearestNeighbor, similarity float64,
	content string, vec pgvector.Vector, category Category,
	ownerID string, sessionID uuid.UUID, expiresAt *time.Time, importance int,
	arb Arbitrator) error {

	// Threshold 1: Auto-merge (>= 0.95).
	if similarity >= AutoMergeThreshold {
		_, err := q.Exec(ctx,
			`UPDATE memories
			 SET content = $1, embedding = $2, updated_at = now(), active = true,
			     category = $3, source_session_id = $4, expires_at = $5, importance = $6
			 WHERE id = $7`,
			content, vec, category, sessionID, expiresAt, importance, nn.id,
		)
		if err != nil {
			return fmt.Errorf("updating duplicate memory: %w", err)
		}
		s.logger.Debug("auto-merged memory", "id", nn.id, "similarity", similarity)
		return nil
	}

	// Threshold 2: Arbitration band [0.85, 0.95).
	if similarity >= ArbitrationThreshold && arb != nil {
		arbCtx, arbCancel := context.WithTimeout(ctx, ArbitrationTimeout)
		defer arbCancel()

		result, arbErr := arb.Arbitrate(arbCtx, nn.content, content)
		if arbErr == nil {
			return s.applyArbitration(ctx, q, result, nn.id, content, vec, category, ownerID, sessionID, expiresAt, importance)
		}
		s.logger.Warn("arbitration failed, falling through to ADD", "error", arbErr)
	}

	// Below thresholds or no arbitrator: INSERT new.
	return s.insertRow(ctx, q, content, vec, category, ownerID, sessionID, expiresAt, importance)
}

// insertRow inserts a new memory row using the provided querier (pool or tx).
// Eviction is the caller's responsibility (see Add).
func (*Store) insertRow(ctx context.Context, q querier, content string, vec pgvector.Vector,
	category Category, ownerID string, sessionID uuid.UUID,
	expiresAt *time.Time, importance int) error {

	_, err := q.Exec(ctx, insertMemorySQL,
		ownerID, content, vec, category, sessionID, expiresAt, importance,
	)
	if err != nil {
		return fmt.Errorf("inserting memory: %w", err)
	}
	return nil
}

// applyArbitration executes the LLM's arbitration decision.
func (s *Store) applyArbitration(ctx context.Context, q querier, result *ArbitrationResult,
	existingID uuid.UUID, content string, vec pgvector.Vector,
	category Category, ownerID string, sessionID uuid.UUID,
	expiresAt *time.Time, importance int) error {

	switch result.Operation {
	case OpNoop:
		s.logger.Debug("arbitration: NOOP, discarding candidate", "existing_id", existingID)
		return nil

	case OpUpdate:
		mergedContent := result.Content
		if mergedContent == "" {
			mergedContent = content // fallback if LLM didn't provide merged content
		}
		if len(mergedContent) > MaxContentLength {
			s.logger.Warn("truncating merged content from arbitration",
				"original_len", len(mergedContent), "max_len", MaxContentLength)
			mergedContent = mergedContent[:MaxContentLength]
		}
		// The LLM may produce merged content containing secrets that weren't
		// in the original candidate (which passed validateAddInput). Re-check.
		if ContainsSecrets(mergedContent) {
			s.logger.Warn("merged content from arbitration contains secrets, using original candidate")
			mergedContent = content // candidate already passed ContainsSecrets
		}
		// Re-embed merged content.
		embedCtx, cancel := context.WithTimeout(ctx, EmbedTimeout)
		defer cancel()
		mergedVec, err := s.embed(embedCtx, mergedContent)
		if err != nil {
			return fmt.Errorf("embedding merged content: %w", err)
		}
		_, err = q.Exec(ctx,
			`UPDATE memories
			 SET content = $1, embedding = $2, updated_at = now(), active = true,
			     category = $3, source_session_id = $4, expires_at = $5, importance = $6
			 WHERE id = $7`,
			mergedContent, mergedVec, category, sessionID, expiresAt, importance, existingID,
		)
		if err != nil {
			return fmt.Errorf("updating memory via arbitration: %w", err)
		}
		s.logger.Debug("arbitration: UPDATE", "id", existingID, "reasoning", truncate(result.Reasoning, 200))
		return nil

	case OpDelete:
		// Soft-delete existing, then insert new (both within the same transaction).
		_, err := q.Exec(ctx,
			`UPDATE memories SET active = false, updated_at = now() WHERE id = $1`,
			existingID,
		)
		if err != nil {
			return fmt.Errorf("soft-deleting via arbitration: %w", err)
		}
		_, err = q.Exec(ctx, insertMemorySQL,
			ownerID, content, vec, category, sessionID, expiresAt, importance,
		)
		if err != nil {
			return fmt.Errorf("inserting after arbitration DELETE: %w", err)
		}
		s.logger.Debug("arbitration: DELETE + ADD", "deleted_id", existingID, "reasoning", truncate(result.Reasoning, 200))
		return nil

	case OpAdd:
		_, err := q.Exec(ctx, insertMemorySQL,
			ownerID, content, vec, category, sessionID, expiresAt, importance,
		)
		if err != nil {
			return fmt.Errorf("inserting via arbitration ADD: %w", err)
		}
		s.logger.Debug("arbitration: ADD", "reasoning", truncate(result.Reasoning, 200))
		return nil

	default:
		s.logger.Warn("unknown arbitration operation, falling through to ADD", "operation", result.Operation)
		_, err := q.Exec(ctx, insertMemorySQL,
			ownerID, content, vec, category, sessionID, expiresAt, importance,
		)
		if err != nil {
			return fmt.Errorf("inserting memory: %w", err)
		}
		return nil
	}
}

// evictIfNeeded removes oldest memories when a user exceeds MaxPerUser.
// Prefers evicting inactive memories first, then oldest active by created_at.
func (s *Store) evictIfNeeded(ctx context.Context, ownerID string) error {
	var count int
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM memories WHERE owner_id = $1 AND active = true`,
		ownerID,
	).Scan(&count); err != nil {
		return fmt.Errorf("counting memories: %w", err)
	}

	if count <= MaxPerUser {
		return nil
	}

	excess := count - MaxPerUser

	// First try to evict inactive memories.
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM memories
		 WHERE id IN (
		   SELECT id FROM memories
		   WHERE owner_id = $1 AND active = false
		   ORDER BY updated_at ASC, id ASC
		   LIMIT $2
		 )`,
		ownerID, excess,
	)
	if err != nil {
		return fmt.Errorf("evicting inactive: %w", err)
	}

	remaining := excess - int(tag.RowsAffected())
	if remaining <= 0 {
		return nil
	}

	// Evict oldest active by created_at.
	_, err = s.pool.Exec(ctx,
		`DELETE FROM memories
		 WHERE id IN (
		   SELECT id FROM memories
		   WHERE owner_id = $1 AND active = true
		   ORDER BY created_at ASC, id ASC
		   LIMIT $2
		 )`,
		ownerID, remaining,
	)
	if err != nil {
		return fmt.Errorf("evicting oldest active: %w", err)
	}

	return nil
}

// Search finds memories similar to the query, filtered by owner.
// Returns up to topK results ordered by cosine similarity descending.
// Excludes superseded and expired memories.
func (s *Store) Search(ctx context.Context, query, ownerID string, topK int) ([]*Memory, error) {
	if query == "" || ownerID == "" {
		return []*Memory{}, nil
	}
	if topK <= 0 {
		topK = 5
	}
	if topK > MaxTopK {
		topK = MaxTopK
	}
	if len(query) > MaxSearchQueryLen {
		query = query[:MaxSearchQueryLen]
	}
	if strings.ContainsRune(query, 0) {
		return []*Memory{}, nil
	}

	embedCtx, cancel := context.WithTimeout(ctx, EmbedTimeout)
	defer cancel()

	vec, err := s.embed(embedCtx, query)
	if err != nil {
		return nil, fmt.Errorf("embedding query: %w", err)
	}

	rows, err := s.pool.Query(ctx,
		`SELECT `+memoryCols+`
		 FROM memories
		 WHERE owner_id = $1 AND active = true
		   AND superseded_by IS NULL
		   AND (expires_at IS NULL OR expires_at > now())
		 ORDER BY embedding <=> $2
		 LIMIT $3`,
		ownerID, vec, topK,
	)
	if err != nil {
		return nil, fmt.Errorf("searching memories: %w", err)
	}
	defer rows.Close()

	return scanMemories(rows)
}

// HybridSearch combines vector similarity, full-text search, and decay score.
// Results are ranked by composite score: 0.6*vector + 0.2*text + 0.2*decay.
// Populates Memory.Score with the composite relevance value.
// Calls UpdateAccess on returned results (log-and-continue on error).
func (s *Store) HybridSearch(ctx context.Context, query, ownerID string, topK int) ([]*Memory, error) {
	if query == "" || ownerID == "" {
		return []*Memory{}, nil
	}
	if topK <= 0 {
		topK = 5
	}
	if topK > MaxTopK {
		topK = MaxTopK
	}
	if len(query) > MaxSearchQueryLen {
		query = query[:MaxSearchQueryLen]
	}
	if strings.ContainsRune(query, 0) {
		return []*Memory{}, nil
	}

	embedCtx, cancel := context.WithTimeout(ctx, EmbedTimeout)
	defer cancel()

	vec, err := s.embed(embedCtx, query)
	if err != nil {
		return nil, fmt.Errorf("embedding query: %w", err)
	}

	rows, err := s.pool.Query(ctx,
		`SELECT `+memoryCols+`,
		        ($4 * (1 - (embedding <=> $1))
		         + $5 * LEAST(1.0, COALESCE(ts_rank_cd(search_text, plainto_tsquery('english', $3), 1), 0))
		         + $6 * decay_score
		        ) AS relevance
		 FROM memories
		 WHERE owner_id = $2
		   AND active = true
		   AND superseded_by IS NULL
		   AND (expires_at IS NULL OR expires_at > now())
		 ORDER BY relevance DESC
		 LIMIT $7`,
		vec, ownerID, query,
		searchWeightVector, searchWeightText, searchWeightDecay,
		topK,
	)
	if err != nil {
		return nil, fmt.Errorf("hybrid searching memories: %w", err)
	}
	defer rows.Close()

	memories, err := scanMemoriesWithScore(rows)
	if err != nil {
		return nil, err
	}

	// Update access tracking (best-effort).
	if len(memories) > 0 {
		ids := make([]uuid.UUID, len(memories))
		for i, m := range memories {
			ids[i] = m.ID
		}
		if accessErr := s.UpdateAccess(ctx, ids); accessErr != nil {
			s.logger.Warn("updating access tracking", "error", accessErr)
		}
	}

	return memories, nil
}

// UpdateAccess increments access_count and sets last_accessed_at for the given IDs.
// Called from HybridSearch with log-and-continue pattern.
//
// Best-effort: runs outside a transaction. A partial update (some rows updated,
// some not) is acceptable — access tracking is advisory, not authoritative.
func (s *Store) UpdateAccess(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	_, err := s.pool.Exec(ctx,
		`UPDATE memories
		 SET access_count = access_count + 1,
		     last_accessed_at = now()
		 WHERE id = ANY($1)`,
		ids,
	)
	if err != nil {
		return fmt.Errorf("updating access for %d memories: %w", len(ids), err)
	}
	return nil
}

// UpdateDecayScores recalculates decay_score for all active memories.
// Processes per-category with batched UPDATEs to avoid large locks.
// Does NOT update updated_at to preserve the decay index.
// Returns total number of rows updated.
//
// The Go-side formula must stay in sync with the SQL expression:
//
//	Go:  math.Exp(-lambda * hours)
//	SQL: exp(-$1 * extract(epoch from (now() - updated_at)) / 3600.0)
//
// NOTE: The explicit $1::float8 cast is required because pgx v5 sends
// Go float64 as an untyped parameter. When PostgreSQL sees `$1 = 0`,
// it infers the parameter as integer, silently truncating 0.001925 → 0.
// The cast forces float8 inference. See: github.com/jackc/pgx/issues/2125
func (s *Store) UpdateDecayScores(ctx context.Context) (int, error) {
	categories := AllCategories()

	var total int
	for _, cat := range categories {
		lambda := cat.DecayLambda()

		tag, err := s.pool.Exec(ctx,
			`UPDATE memories
			 SET decay_score = CASE
			     WHEN $1::float8 = 0.0 THEN 1.0
			     ELSE LEAST(1.0, exp(-$1::float8 * extract(epoch from (now() - updated_at)) / 3600.0))
			 END
			 WHERE active = true
			   AND superseded_by IS NULL
			   AND category = $2`,
			lambda, string(cat),
		)
		if err != nil {
			return total, fmt.Errorf("updating decay scores for %s: %w", cat, err)
		}
		total += int(tag.RowsAffected())
	}

	return total, nil
}

// DeleteStale soft-deletes memories past their expires_at timestamp.
// Operates globally (all owners). Returns number of memories expired.
func (s *Store) DeleteStale(ctx context.Context) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE memories
		 SET active = false, updated_at = now()
		 WHERE active = true
		   AND expires_at IS NOT NULL
		   AND expires_at < now()`,
	)
	if err != nil {
		return 0, fmt.Errorf("expiring stale memories: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// All returns all active memories for a user, optionally filtered by category.
// When category is empty, returns all categories.
// Excludes superseded and expired memories.
func (s *Store) All(ctx context.Context, ownerID string, category Category) ([]*Memory, error) {
	if ownerID == "" {
		return []*Memory{}, nil
	}

	var rows pgx.Rows
	var err error

	if category != "" {
		if !category.Valid() {
			return nil, fmt.Errorf("invalid category: %q", category)
		}
		rows, err = s.pool.Query(ctx,
			`SELECT `+memoryCols+`
			 FROM memories
			 WHERE owner_id = $1 AND active = true AND category = $2
			   AND superseded_by IS NULL
			   AND (expires_at IS NULL OR expires_at > now())
			 ORDER BY updated_at DESC`,
			ownerID, category,
		)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT `+memoryCols+`
			 FROM memories
			 WHERE owner_id = $1 AND active = true
			   AND superseded_by IS NULL
			   AND (expires_at IS NULL OR expires_at > now())
			 ORDER BY updated_at DESC`,
			ownerID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing memories: %w", err)
	}
	defer rows.Close()

	return scanMemories(rows)
}

// Delete soft-deletes a memory by setting active = false.
// Returns ErrNotFound if the memory doesn't exist.
// Returns ErrForbidden if the memory belongs to a different owner.
func (s *Store) Delete(ctx context.Context, id uuid.UUID, ownerID string) error {
	// Atomic update: only modifies if both id and owner match.
	tag, err := s.pool.Exec(ctx,
		`UPDATE memories SET active = false, updated_at = now()
		 WHERE id = $1 AND owner_id = $2`,
		id, ownerID,
	)
	if err != nil {
		return fmt.Errorf("soft-deleting memory %s: %w", id, err)
	}

	if tag.RowsAffected() == 0 {
		// Distinguish not-found vs forbidden.
		var memOwner string
		lookupErr := s.pool.QueryRow(ctx,
			`SELECT owner_id FROM memories WHERE id = $1`,
			id,
		).Scan(&memOwner)
		if errors.Is(lookupErr, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if lookupErr != nil {
			return fmt.Errorf("looking up memory %s: %w", id, lookupErr)
		}
		return ErrForbidden
	}

	return nil
}

// DeleteAll soft-deletes all active memories for a user.
func (s *Store) DeleteAll(ctx context.Context, ownerID string) error {
	if ownerID == "" {
		return fmt.Errorf("owner ID is required")
	}

	_, err := s.pool.Exec(ctx,
		`UPDATE memories SET active = false, updated_at = now()
		 WHERE owner_id = $1 AND active = true`,
		ownerID,
	)
	if err != nil {
		return fmt.Errorf("soft-deleting all memories: %w", err)
	}

	return nil
}

// Supersede marks an old memory as superseded by a new one.
// Validation:
//  1. Self-reference check: oldID == newID → error
//  2. Owner match: atomic UPDATE ensures same owner_id
//  3. Double-supersede guard: WHERE superseded_by IS NULL
//  4. Cycle detection: walks chain up to 10 levels
func (s *Store) Supersede(ctx context.Context, oldID, newID uuid.UUID) error {
	if oldID == newID {
		return fmt.Errorf("memory cannot supersede itself")
	}

	// Cycle detection: walk from newID up the chain.
	current := newID
	for depth := 0; depth < 10; depth++ {
		var next *uuid.UUID
		err := s.pool.QueryRow(ctx,
			"SELECT superseded_by FROM memories WHERE id = $1", current,
		).Scan(&next)
		if err != nil || next == nil {
			break
		}
		if *next == oldID {
			return fmt.Errorf("circular supersession chain detected")
		}
		current = *next
	}

	// Atomic: only supersede if same owner and not already superseded.
	tag, err := s.pool.Exec(ctx,
		`UPDATE memories
		 SET superseded_by = $2, active = false, updated_at = now()
		 WHERE id = $1
		   AND owner_id = (SELECT owner_id FROM memories WHERE id = $2)
		   AND superseded_by IS NULL`,
		oldID, newID,
	)
	if err != nil {
		return fmt.Errorf("superseding memory %s: %w", oldID, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// scanMemories reads Memory structs from pgx.Rows (standard column set).
func scanMemories(rows pgx.Rows) ([]*Memory, error) {
	var memories []*Memory
	for rows.Next() {
		m := &Memory{}
		var sessionID *uuid.UUID
		if err := rows.Scan(
			&m.ID, &m.OwnerID, &m.Content, &m.Category,
			&sessionID, &m.Active, &m.CreatedAt, &m.UpdatedAt,
			&m.Importance, &m.AccessCount, &m.LastAccessedAt,
			&m.DecayScore, &m.SupersededBy, &m.ExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("scanning memory: %w", err)
		}
		if sessionID != nil {
			m.SourceSessionID = *sessionID
		}
		memories = append(memories, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating memories: %w", err)
	}
	return memories, nil
}

// scanMemoriesWithScore reads Memory structs plus a trailing relevance score column.
// Used by HybridSearch to populate Memory.Score.
func scanMemoriesWithScore(rows pgx.Rows) ([]*Memory, error) {
	var memories []*Memory
	for rows.Next() {
		m := &Memory{}
		var sessionID *uuid.UUID
		if err := rows.Scan(
			&m.ID, &m.OwnerID, &m.Content, &m.Category,
			&sessionID, &m.Active, &m.CreatedAt, &m.UpdatedAt,
			&m.Importance, &m.AccessCount, &m.LastAccessedAt,
			&m.DecayScore, &m.SupersededBy, &m.ExpiresAt,
			&m.Score,
		); err != nil {
			return nil, fmt.Errorf("scanning memory with score: %w", err)
		}
		if sessionID != nil {
			m.SourceSessionID = *sessionID
		}
		memories = append(memories, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating memories: %w", err)
	}
	return memories, nil
}

// FormatMemories renders memories into a prompt-ready string using greedy priority.
// Categories are rendered in order: identity > preference > project > contextual.
// Each section only appears if it has memories. Budget flows from higher to lower
// priority categories — remaining tokens from identity flow to preference, etc.
//
// Memory content is sanitized to prevent prompt injection via XML-like tags.
func FormatMemories(identity, preference, project, contextual []*Memory, maxTokens int) string {
	if len(identity) == 0 && len(preference) == 0 && len(project) == 0 && len(contextual) == 0 {
		return ""
	}

	maxChars := maxTokens * 4 // rough estimate: 1 token ~ 4 chars
	var b []byte

	type section struct {
		header   string
		memories []*Memory
	}
	sections := []section{
		{"What I know about you:\n", identity},
		{"Your preferences:\n", preference},
		{"Your current projects:\n", project},
		{"Relevant context for this conversation:\n", contextual},
	}

	for _, sec := range sections {
		if len(sec.memories) == 0 {
			continue
		}
		if len(b) > 0 {
			b = append(b, '\n')
		}
		// Check if header itself would exceed budget.
		if len(b)+len(sec.header) > maxChars {
			break
		}
		b = append(b, sec.header...)
		for _, m := range sec.memories {
			line := "- " + sanitizeMemoryContent(m.Content) + "\n"
			if len(b)+len(line) > maxChars {
				break
			}
			b = append(b, line...)
		}
	}

	return string(b)
}

// sanitizeMemoryContent prevents prompt injection when memory content is
// injected into the live chat prompt. Two layers of defense:
//  1. Strip angle brackets — prevents XML/HTML tag injection (e.g., </user_memories>).
//  2. Collapse newlines to spaces — prevents instruction separation from context.
//
// The LLM-side instruction boundary (section headers) is the primary containment;
// this function is a secondary defense-in-depth layer.
func sanitizeMemoryContent(s string) string {
	s = strings.NewReplacer(
		"<", "",
		">", "",
		"`", "",
		"\n", " ",
		"\r", " ",
	).Replace(s)
	return s
}

// decayScore calculates the exponential decay score for a given elapsed time.
// Used for testing and reference. Production uses SQL-level calculation.
//
// Must stay in sync with the SQL formula in UpdateDecayScores:
//
//	exp(-lambda * extract(epoch from (now() - updated_at)) / 3600.0)
func decayScore(lambda float64, elapsed time.Duration) float64 {
	if lambda == 0 {
		return 1.0
	}
	hours := elapsed.Hours()
	score := math.Exp(-lambda * hours)
	if score > 1.0 {
		return 1.0
	}
	return score
}
