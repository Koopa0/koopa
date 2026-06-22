// Copyright 2026 Koopa. All rights reserved.

package embedder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pgvector/pgvector-go"
)

// reconcileBatchSize is how many missing rows each drain iteration fetches
// per source. Small enough that one batch's Gemini calls finish well inside
// a reconcile interval; large enough that a backfill is not dominated by
// query round-trips.
const reconcileBatchSize = 50

// maxEmbedBodyBytes caps how much of a row's body is sent to the embedding
// API. The Gemini embedding endpoint bounds input length per request and
// the exact byte equivalent of that token bound is not published, so a
// conservative 30KB cap is applied locally; the title plus leading body
// dominate a single-vector representation, so the truncated tail costs
// little recall.
const maxEmbedBodyBytes = 30 * 1024

// TextEmbedder is the reconciler's seam over the Gemini-backed *Embedder.
// The interface exists because reconciler tests must run without network
// access — *Embedder is the only production implementation.
type TextEmbedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}

var _ TextEmbedder = (*Embedder)(nil)

// Document is one row awaiting an embedding: the identity plus the text
// fields the embedding derives from.
type Document struct {
	ID    uuid.UUID
	Title string
	Body  string
}

// Source is a store whose rows the reconciler keeps embedded. Implemented by
// *content.Store and the reading / song embedding sources.
type Source interface {
	// MissingEmbeddings returns up to limit rows whose embedding is NULL,
	// oldest first.
	MissingEmbeddings(ctx context.Context, limit int) ([]Document, error)
	// SetEmbedding persists the vector for one row. It must not touch any
	// other column — embeddings are derived data, not edits.
	SetEmbedding(ctx context.Context, id uuid.UUID, embedding pgvector.Vector) error
}

// NamedSource pairs a Source with the label used to key its progress in
// Result.BySource and to tag its log lines. Name is a stable, short
// identifier (e.g. "contents", "readings", "reading_reflections").
type NamedSource struct {
	Name   string
	Source Source
}

// Result counts what one RunOnce pass did. BySource maps each source's name to
// the number of rows it embedded this pass (a source that embedded nothing is
// still present with a zero count). Failed is the total embed-or-persist
// failures across all sources — those rows keep a NULL embedding and are
// picked up again on a later pass, so a row that fails repeatedly within one
// pass is counted once per attempt.
type Result struct {
	BySource map[string]int
	Failed   int
}

// Reconciler keeps every wired source's embedding column current by embedding
// rows whose embedding is NULL. It runs outside any request path or
// transaction: the Gemini call is slow, networked, and must never sit inside a
// handler's per-request tx.
type Reconciler struct {
	embedder TextEmbedder
	sources  []NamedSource
	logger   *slog.Logger
}

// NewReconciler returns a Reconciler over the given named sources. The
// embedder, logger, and at least one source are required, and every source
// must carry a non-nil Source and a non-empty, unique Name — a misconfigured
// reconciler is a wiring bug, surfaced at startup rather than as silent
// dropped work.
func NewReconciler(e TextEmbedder, logger *slog.Logger, sources ...NamedSource) *Reconciler {
	if e == nil || logger == nil {
		panic("embedder: NewReconciler requires non-nil embedder and logger")
	}
	if len(sources) == 0 {
		panic("embedder: NewReconciler requires at least one source")
	}
	seen := make(map[string]bool, len(sources))
	for _, ns := range sources {
		if ns.Source == nil || ns.Name == "" {
			panic("embedder: NewReconciler requires every source to have a non-nil Source and a non-empty Name")
		}
		if seen[ns.Name] {
			panic("embedder: NewReconciler requires unique source names, got duplicate " + ns.Name)
		}
		seen[ns.Name] = true
	}
	return &Reconciler{embedder: e, sources: sources, logger: logger}
}

// RunOnce drains every source in registration order, each in batches of
// reconcileBatchSize until no missing rows remain. Per-row failures are
// logged, counted in Result.Failed, and skipped — the row stays NULL for the
// next pass. The returned error joins any source-level failures (a listing
// query that errored, or ctx cancellation); Result still carries whatever
// progress was made before it. Result.BySource always has an entry for every
// wired source, even one that embedded nothing.
func (r *Reconciler) RunOnce(ctx context.Context) (Result, error) {
	res := Result{BySource: make(map[string]int, len(r.sources))}
	var errs []error

	for _, ns := range r.sources {
		embedded, failed, err := r.drain(ctx, ns.Source, ns.Name)
		res.BySource[ns.Name] = embedded
		res.Failed += failed
		if err != nil {
			errs = append(errs, fmt.Errorf("draining %s: %w", ns.Name, err))
		}
	}
	return res, errors.Join(errs...)
}

// Run reconciles once immediately, then again on every interval tick,
// until ctx is cancelled. It owns no goroutine — the caller launches it
// and waits for it during shutdown.
func (r *Reconciler) Run(ctx context.Context, interval time.Duration) {
	r.runPass(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runPass(ctx)
		}
	}
}

// runPass executes one RunOnce and reports its outcome. Cancellation
// mid-pass is shutdown, not failure — logged at debug. A quiet pass (no
// work, no failures) logs nothing so a 60s interval does not flood the
// log.
func (r *Reconciler) runPass(ctx context.Context) {
	res, err := r.RunOnce(ctx)
	attrs := passLogAttrs(res)
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		r.logger.Debug("embedding pass interrupted", attrs...)
	case err != nil:
		r.logger.Error("embedding pass failed", append(attrs, "error", err)...)
	case res.totalEmbedded() > 0 || res.Failed > 0:
		r.logger.Info("embedding pass complete", attrs...)
	}
}

// passLogAttrs flattens a Result into slog key/value pairs: one key per source
// (its embedded count) plus the failed total. Sorting the source names keeps
// log output deterministic across passes.
func passLogAttrs(res Result) []any {
	names := make([]string, 0, len(res.BySource))
	for name := range res.BySource {
		names = append(names, name)
	}
	slices.Sort(names)
	attrs := make([]any, 0, len(names)*2+2)
	for _, name := range names {
		attrs = append(attrs, name, res.BySource[name])
	}
	attrs = append(attrs, "failed", res.Failed)
	return attrs
}

// totalEmbedded sums the per-source embedded counts.
func (res Result) totalEmbedded() int {
	total := 0
	for _, n := range res.BySource {
		total += n
	}
	return total
}

// drain embeds src's missing rows batch by batch until none remain. A
// batch in which every row failed ends the drain instead of refetching
// the same NULL rows forever; a short batch means the source is drained
// apart from rows that just failed, which wait for the next pass.
func (r *Reconciler) drain(ctx context.Context, src Source, name string) (embedded, failed int, err error) {
	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return embedded, failed, ctxErr
		}
		batch, listErr := src.MissingEmbeddings(ctx, reconcileBatchSize)
		if listErr != nil {
			return embedded, failed, fmt.Errorf("listing rows missing embeddings: %w", listErr)
		}
		if len(batch) == 0 {
			return embedded, failed, nil
		}

		succeeded := 0
		for _, doc := range batch {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return embedded, failed, ctxErr
			}
			if embedErr := r.embedOne(ctx, src, doc); embedErr != nil {
				failed++
				r.logger.Warn("embedding row skipped",
					"source", name, "id", doc.ID, "error", embedErr)
				continue
			}
			succeeded++
			embedded++
		}

		if succeeded == 0 || len(batch) < reconcileBatchSize {
			return embedded, failed, nil
		}
	}
}

// embedOne builds the document text, embeds it, and persists the vector.
func (r *Reconciler) embedOne(ctx context.Context, src Source, doc Document) error {
	vec, err := r.embedder.Embed(ctx, embedText(doc.Title, doc.Body))
	if err != nil {
		return fmt.Errorf("embedding: %w", err)
	}
	if err := src.SetEmbedding(ctx, doc.ID, pgvector.NewVector(vec)); err != nil {
		return fmt.Errorf("persisting embedding: %w", err)
	}
	return nil
}

// embedText joins title and body into the embedding input, capping the
// body at maxEmbedBodyBytes. The cut lands on a rune boundary — bodies
// are frequently CJK and a split rune would send invalid UTF-8 to the
// API. Title is never blank (schema-enforced for contents), so the
// input is never empty.
func embedText(title, body string) string {
	if len(body) > maxEmbedBodyBytes {
		body = truncateUTF8(body, maxEmbedBodyBytes)
	}
	if body == "" {
		return title
	}
	return title + "\n\n" + body
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
