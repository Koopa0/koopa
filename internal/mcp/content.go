// Copyright 2026 Koopa. All rights reserved.

// content.go contains the internal workhorses behind the flat content
// MCP tools declared in content_tools.go. It defines the shared
// ManageContentInput shape, the per-transition internal methods
// (createContent, updateContent, publishContent, …), and the
// publish-authority guard (publish requires an explicit `as: "human"`)
// plus the publish state guard (review-gated: only status=review
// transitions; already-published is an idempotent no-op; draft/archived
// are rejected).
//
// Why the split: the MCP surface is flat, but the internal logic
// branches on the transition being requested. Keeping the branch logic
// here (one file) instead of spreading it across eight handlers keeps
// the publish-authority and state-machine rules in one reviewable place.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/content"
)

// ManageContentInput is the INTERNAL shared input shape used by the flat
// content tool handlers (create_content / update_content / publish_content /
// etc.). The `manage_content` multiplexer was removed — the
// top-level MCP surface is 8 flat tools defined in content_tools.go. Each
// flat tool has its own tight input struct and fills this shared shape to
// call the internal method.
//
// The struct name stays exported because an older integration test still
// constructs it directly; internal-only flows use the per-tool wrappers.
type ManageContentInput struct {
	ContentID   *string
	Slug        *string
	Title       *string
	Body        *string
	ContentType *string
	Status      *string
	Project     *string
	Limit       FlexInt

	// Redirect-only fields — the internal validators accept them to emit
	// a 'use manage_note' redirect error. No flat tool exposes these.
	NoteKind         *string
	Maturity         *string
	LearningTargetID *string
	ConceptSlugs     []string
}

// Closed sets for handler-side validation. Matches schema CHECK constraints
// at migrations/001_initial.up.sql.
//
// validNoteKinds / validMaturityStages were removed in the notes-extraction cleanup —
// after schema cleanup extracted notes to their own entity, the validators on
// the content path only check that NoteKind / Maturity are NOT set (and emit
// a redirect-to-manage_note error). The enum vocabulary lives in
// internal/note.Kind / internal/note.Maturity now; the manage_note MCP tool
// validates against those types.
var (
	// validContentTypes mirrors the content_type ENUM in
	// migrations/001_initial.up.sql after schema cleanup extracted notes to
	// their own entity. 'note' is no longer a content sub-type — use the
	// manage_note MCP tool (or internal/note directly) for Zettelkasten
	// notes. 'bookmark' was never a content type in this schema — see
	// internal/bookmark.
	validContentTypes = map[string]struct{}{
		"article":   {},
		"essay":     {},
		"build-log": {},
		"til":       {},
		"digest":    {},
	}
)

// ContentSummary is a lightweight content record for list results.
type ContentSummary struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updated_at"`
}

// ContentDetail is a full content record for read/create/update/publish results.
type ContentDetail struct {
	ID        string   `json:"id"`
	Slug      string   `json:"slug"`
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	Excerpt   string   `json:"excerpt"`
	Type      string   `json:"type"`
	Status    string   `json:"status"`
	Tags      []string `json:"tags,omitempty"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

// SlugConflictInfo carries the existing content row's identity when a
// create/update attempt collides with an existing slug. Surfaced via
// ManageContentOutput.SlugConflict without an error so clients can decide
// whether to switch to action=update or pick a new slug.
type SlugConflictInfo struct {
	Slug      string `json:"slug"`
	ContentID string `json:"content_id"`
}

// ManageContentOutput is the response shape for every content tool
// (create, update, publish, archive, submit_for_review,
// revert_to_draft, list, read). The struct tags here are informational;
// MarshalJSON below decides actual per-action emission. The list action
// always emits contents:[] and total; other actions omit those keys.
type ManageContentOutput struct {
	Content  *ContentDetail   `json:"content,omitempty"`
	Contents []ContentSummary `json:"contents,omitempty"`
	Total    int              `json:"total,omitempty"`
	Action   string           `json:"action"`
	// ContentWarnings is create-only. Only the createContent path emits warnings
	// (slug normalization, etc.) — every other action (update, publish, list,
	// read, archive, submit_for_review, revert_to_draft, slug_conflict-on-create)
	// constructs ManageContentOutput without setting this field. omitempty is
	// therefore the correct shape: present (possibly empty) on create, absent on
	// every other action. Contrast with learning.go's RecordAttemptOutput where
	// every action can produce warnings, so always-present is the right pattern.
	ContentWarnings []string          `json:"content_warnings,omitempty"`
	SlugConflict    *SlugConflictInfo `json:"slug_conflict,omitempty"`
}

// MarshalJSON enforces the per-action wire shape. The list action always
// emits contents:[] (never null, never absent) and total alongside it.
// Other actions omit those fields entirely so create/update/etc.
// responses don't carry empty list noise. Mirrors the pattern used by
// LearningDashboardOutput.
func (o ManageContentOutput) MarshalJSON() ([]byte, error) {
	base := map[string]any{"action": o.Action}
	switch o.Action {
	case "list":
		base["contents"] = ensureSlice(o.Contents)
		base["total"] = o.Total
	case "create":
		// ContentWarnings is create-only and ALWAYS present (possibly
		// empty) per the field's doc comment. ensureSlice keeps the
		// shape stable even when the create path emits zero warnings.
		base["content_warnings"] = ensureSlice(o.ContentWarnings)
		if o.Content != nil {
			base["content"] = o.Content
		}
	default:
		if o.Content != nil {
			base["content"] = o.Content
		}
	}
	if o.SlugConflict != nil {
		base["slug_conflict"] = o.SlugConflict
	}
	return json.Marshal(base)
}

// manage_content multiplexer removed in the notes/content split — 8 flat per-intent
// tools replace it (see content_tools.go). Internal handlers below
// (createContent, updateContent, ...) are now called by those flat tools
// rather than by a dispatcher.

// validateCreateContentFields runs the handler-side validation for
// createContent (before the tx opens). Note: notes moved out of
// contents, so the note_kind / maturity branches here are now hard errors
// that redirect callers to the manage_note tool.
func validateCreateContentFields(input *ManageContentInput) error {
	if input.Title == nil || *input.Title == "" {
		return fmt.Errorf("title is required for create")
	}
	if input.ContentType == nil || *input.ContentType == "" {
		return fmt.Errorf("content_type is required for create")
	}
	if _, ok := validContentTypes[*input.ContentType]; !ok {
		if *input.ContentType == "note" {
			return fmt.Errorf("content_type='note' is no longer valid — notes are a separate entity. Use the manage_note tool (or internal/note) for Zettelkasten notes")
		}
		return fmt.Errorf("invalid content_type %q (one of: article, essay, build-log, til, digest)", *input.ContentType)
	}
	if input.NoteKind != nil && *input.NoteKind != "" {
		return fmt.Errorf("note_kind is not a content field — notes are a separate entity. Use manage_note")
	}
	if input.Maturity != nil && *input.Maturity != "" {
		return fmt.Errorf("maturity is not a content field — notes are a separate entity. Use manage_note")
	}
	if input.Slug != nil && *input.Slug != "" {
		if err := validateSlug("content slug", *input.Slug); err != nil {
			return err
		}
	}
	return nil
}

// validateUpdateContentFields runs the handler-side validation for
// updateContent. Unlike create, every field is optional — validation only
// fires on the fields the caller actually sent. Returns nil on success.
func validateUpdateContentFields(input *ManageContentInput) error {
	if input.ContentType != nil && *input.ContentType != "" {
		if _, ok := validContentTypes[*input.ContentType]; !ok {
			return fmt.Errorf("invalid content_type %q (one of: article, essay, build-log, til, digest)", *input.ContentType)
		}
	}
	// No status validation here: update_content is fields-only. updateContentTool
	// rejects any status field at the boundary (Track 1E-correction), and this
	// internal method never forwards a status to the store — so validating one
	// here would be dead code that misleads readers.
	if input.NoteKind != nil && *input.NoteKind != "" {
		return fmt.Errorf("note_kind is not a content field — notes are a separate entity. Use manage_note")
	}
	if input.Maturity != nil && *input.Maturity != "" {
		return fmt.Errorf("maturity is not a content field — notes are a separate entity. Use manage_note")
	}
	// Mirror createContent's slug validation (handler-consistency): a
	// caller-supplied slug is rejected here with a caller-facing message
	// rather than leaking the chk_content_slug_format CheckViolation from
	// PG. update has no title-derived fallback — it only writes a slug the
	// caller explicitly sent — so this single check covers the path.
	if input.Slug != nil && *input.Slug != "" {
		if err := validateSlug("content slug", *input.Slug); err != nil {
			return err
		}
	}
	return nil
}

// conceptRefsFromIDs wraps a slug-resolved concept ID list into ConceptRef
// slice with the convention: first = primary, remainder = secondary. The
// MCP tool expresses primacy by ordering; the partial-unique one-primary
// index then enforces it structurally.
func conceptRefsFromIDs(ids []uuid.UUID) []content.ConceptRef {
	if len(ids) == 0 {
		return nil
	}
	refs := make([]content.ConceptRef, len(ids))
	for i, id := range ids {
		rel := "secondary"
		if i == 0 {
			rel = "primary"
		}
		refs[i] = content.ConceptRef{ID: id, Relevance: rel}
	}
	return refs
}

// resolveConceptIDs looks up a batch of concept slugs and returns their UUIDs
// in the same order as the input. Unknown slugs produce an ErrInvalidInput-
// shaped error listing every missing slug so the caller fixes them in one
// round trip instead of discovering them one at a time.
func (s *Server) resolveConceptIDs(ctx context.Context, slugs []string) ([]uuid.UUID, error) {
	if len(slugs) == 0 {
		return nil, nil
	}
	resolved, err := s.learn.ConceptIDsBySlug(ctx, slugs)
	if err != nil {
		return nil, fmt.Errorf("resolving concept_slugs: %w", err)
	}
	conceptIDs := make([]uuid.UUID, 0, len(slugs))
	missing := make([]string, 0)
	for _, sl := range slugs {
		id, ok := resolved[sl]
		if !ok {
			missing = append(missing, sl)
			continue
		}
		conceptIDs = append(conceptIDs, id)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("unknown concept slugs: %v", missing)
	}
	return conceptIDs, nil
}

// deriveCreateSlug prefers the caller-supplied slug when present and falls
// back to a title-derived slug. Not a canonical slugifier — learning-studio
// generates its own slugs (lc-33-search-rotated, etc.) and passes them in
// via input.Slug; this fallback is only for admin UI callers who don't care.
func deriveCreateSlug(input *ManageContentInput) string {
	if input.Slug != nil && *input.Slug != "" {
		return *input.Slug
	}
	return strings.ToLower(strings.ReplaceAll(*input.Title, " ", "-"))
}

// createWarnings computes soft warnings for post-write reply. Not errors —
// the note was created; these signal that the caller probably meant to
// provide a learning_target_id (for solve-note) or concept_slugs (for
// concept-note). See Koopa-Learning.md Step 9 anti-patterns.
func createWarnings(input *ManageContentInput, learningTargetID *uuid.UUID, conceptIDs []uuid.UUID) []string {
	warnings := make([]string, 0)
	if input.NoteKind == nil {
		return warnings
	}
	switch *input.NoteKind {
	case "solve-note":
		if learningTargetID == nil {
			warnings = append(warnings, "missing_target")
		}
	case "concept-note":
		if len(conceptIDs) == 0 {
			warnings = append(warnings, "missing_concepts")
		}
	}
	return warnings
}

// createContent drafts a content row in status=draft. Authoring is gated
// by the author allowlist: content-studio and learning-studio are the
// cowork agents whose role is producing content; human is always implicit
// (see authz.go::requireAuthor). Other agents (hq, research-lab) route
// content work to content-studio via a directive rather than drafting
// directly. The separate dangerous transition (review → published) is
// human-gated at publish_content; every draft is private until then.
func (s *Server) createContent(ctx context.Context, input *ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if err := s.requireAuthor(ctx, "create_content", "content-studio", "learning-studio"); err != nil {
		return nil, ManageContentOutput{}, err
	}
	if err := validateCreateContentFields(input); err != nil {
		return nil, ManageContentOutput{}, err
	}

	// Validate the slug we will actually insert before any I/O.
	// validateCreateContentFields already checks a caller-supplied slug, but
	// the title-derived fallback (deriveCreateSlug) can still produce a
	// non-conforming slug for non-ASCII or punctuated titles ("[TEST] 標題" →
	// "[test]-標題") — without this check that surfaces as a raw
	// chk_content_slug_format CheckViolation from PG instead of a caller-facing
	// message. Kept above resolveConceptIDs so a bad slug fails fast without
	// spending a DB round-trip.
	slug := deriveCreateSlug(input)
	if err := validateSlug("content slug", slug); err != nil {
		return nil, ManageContentOutput{}, err
	}

	var learningTargetID *uuid.UUID
	if input.LearningTargetID != nil && *input.LearningTargetID != "" {
		id, parseErr := uuid.Parse(*input.LearningTargetID)
		if parseErr != nil {
			return nil, ManageContentOutput{}, fmt.Errorf("invalid learning_target_id: %w", parseErr)
		}
		learningTargetID = &id
	}

	conceptIDs, err := s.resolveConceptIDs(ctx, input.ConceptSlugs)
	if err != nil {
		return nil, ManageContentOutput{}, err
	}

	body := ""
	if input.Body != nil {
		body = *input.Body
	}
	var projectID *uuid.UUID
	if input.Project != nil && *input.Project != "" {
		projectID = s.resolveProjectID(ctx, *input.Project)
	}

	var c *content.Content
	txErr := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var createErr error
		c, createErr = content.NewStore(tx).CreateContent(ctx, &content.CreateParams{
			Slug:      slug,
			Title:     *input.Title,
			Body:      body,
			Type:      content.Type(*input.ContentType),
			Status:    content.StatusDraft,
			ProjectID: projectID,
			Concepts:  conceptRefsFromIDs(conceptIDs),
		})
		return createErr
	})
	if txErr != nil {
		if slugErr, ok := errors.AsType[*content.SlugConflictError](txErr); ok {
			return nil, ManageContentOutput{
				Action: "create",
				SlugConflict: &SlugConflictInfo{
					Slug:      slugErr.Slug,
					ContentID: slugErr.ContentID.String(),
				},
			}, nil
		}
		return nil, ManageContentOutput{}, fmt.Errorf("creating content: %w", txErr)
	}

	warnings := createWarnings(input, learningTargetID, conceptIDs)
	s.logger.Info("manage_content", "action", "create", "id", c.ID, "warnings", len(warnings))
	return nil, ManageContentOutput{
		Content:         toContentDetail(c),
		Action:          "create",
		ContentWarnings: warnings,
	}, nil
}

func (s *Server) updateContent(ctx context.Context, input *ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if err := s.requireAuthor(ctx, "update_content", "content-studio", "learning-studio"); err != nil {
		return nil, ManageContentOutput{}, err
	}
	if input.ContentID == nil || *input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required for update")
	}
	id, err := uuid.Parse(*input.ContentID)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("invalid content_id: %w", err)
	}

	if validateErr := validateUpdateContentFields(input); validateErr != nil {
		return nil, ManageContentOutput{}, validateErr
	}

	var ct *content.Type
	if input.ContentType != nil && *input.ContentType != "" {
		t := content.Type(*input.ContentType)
		ct = &t
	}

	// update_content is fields-only: it MUST NOT change status. Status
	// transitions are owned by the dedicated lifecycle tools
	// (set_content_review_state / publish_content /
	// archive_content via transitionContentStatus / publishContent). The tool
	// boundary (updateContentTool) rejects a status field; here we structurally
	// never forward one to the store, so even an internal caller cannot move
	// status through this path.
	var c *content.Content
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		c, err = content.NewStore(tx).UpdateContent(ctx, id, &content.UpdateParams{
			Title: input.Title,
			Body:  input.Body,
			Type:  ct,
			Slug:  input.Slug,
		})
		return err
	})
	if err != nil {
		if slugErr, ok := errors.AsType[*content.SlugConflictError](err); ok {
			return nil, ManageContentOutput{
				Action: "update",
				SlugConflict: &SlugConflictInfo{
					Slug:      slugErr.Slug,
					ContentID: slugErr.ContentID.String(),
				},
			}, nil
		}
		return nil, ManageContentOutput{}, fmt.Errorf("updating content: %w", err)
	}

	s.logger.Info("manage_content", "action", "update", "id", c.ID)
	return nil, ManageContentOutput{Content: toContentDetail(c), Action: "update"}, nil
}

func (s *Server) publishContent(ctx context.Context, input *ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.ContentID == nil || *input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required for publish")
	}
	id, err := uuid.Parse(*input.ContentID)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("invalid content_id: %w", err)
	}

	// Publishing is a human-only REVIEW transition per the editorial
	// lifecycle (agent drafts and submits for review; human publishes).
	// See authz.go for why requireExplicitHuman refuses the server default.
	if err := s.requireExplicitHuman(ctx, "publish_content"); err != nil {
		return nil, ManageContentOutput{}, err
	}
	_, callerName := s.ExplicitCallerIdentity(ctx)

	// State guard. publish_content is review-gated: only a review row
	// transitions, an already-published row is an idempotent no-op, and any
	// other state (draft, archived, …) is rejected without mutating the row.
	// The policy lives in content.Store.PublishFromReview — the single
	// enforcement point shared with the HTTP admin publish handler so the two
	// boundaries cannot drift. Runs inside the actor tx for correct audit
	// attribution.
	var c *content.Content
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var pErr error
		c, pErr = content.NewStore(tx).PublishFromReview(ctx, id)
		return pErr
	})
	if err != nil {
		if errors.Is(err, content.ErrNotFound) {
			return nil, ManageContentOutput{}, fmt.Errorf("content %s not found", id)
		}
		if errors.Is(err, content.ErrInvalidState) {
			return nil, ManageContentOutput{}, fmt.Errorf("content %s is not in review state; publish requires status=review", id)
		}
		return nil, ManageContentOutput{}, fmt.Errorf("publishing content: %w", err)
	}

	s.logger.Info("manage_content", "action", "publish", "id", c.ID, "caller", callerName)
	return nil, ManageContentOutput{Content: toContentDetail(c), Action: "publish"}, nil
}

// transitionContentStatus enforces a guarded content lifecycle transition at
// the MCP tool boundary — the canonical enforcement point (catalog.go and
// docs/testing/content-lifecycle-mcp-contract.md describe the intended
// semantics; this is where they are made real). It reads the current row
// inside the actor tx and:
//
//   - if already in target: returns the row unchanged (idempotent no-op — no
//     mutation, so the audit trigger fires no second state_changed/archived event);
//   - if the current status is an allowed source: applies the status change
//     (audit trigger fires exactly one event);
//   - otherwise: returns content.ErrInvalidState WITHOUT mutating the row.
//
// content.ErrNotFound propagates for a missing id; a malformed UUID returns a
// validation error. The mutation uses the generic UpdateContent(status=target)
// — safe because the allowed transitions (draft↔review, draft/review→archived)
// never set published_at, so chk_content_publication cannot fire. This mirrors
// publishContent's read-then-act pattern (Track 1D); the same small race window
// applies and is acceptable for these low-frequency admin operations.
func (s *Server) transitionContentStatus(ctx context.Context, idStr string, target content.Status, allowed ...content.Status) (*content.Content, error) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("invalid content_id: %w", err)
	}
	var out *content.Content
	txErr := s.withActorTx(ctx, func(tx pgx.Tx) error {
		store := content.NewStore(tx)
		current, err := store.Content(ctx, id)
		if err != nil {
			return err // ErrNotFound mapped by the caller
		}
		if current.Status == target {
			out = current // idempotent no-op
			return nil
		}
		if slices.Contains(allowed, current.Status) {
			updated, uErr := store.UpdateContent(ctx, id, &content.UpdateParams{Status: &target})
			if uErr != nil {
				return uErr
			}
			out = updated
			return nil
		}
		return content.ErrInvalidState
	})
	return out, txErr
}

// mapContentTransitionErr converts the sentinels from transitionContentStatus
// into client-facing tool errors. op is the tool name; requirement names the
// allowed source state(s) for the invalid-state message.
//
// Chain discipline: the two known sentinels (ErrNotFound, ErrInvalidState) are
// DELIBERATELY rendered as terminal client messages without %w — they are the
// final string the MCP caller sees and nothing above branches on them. Only the
// unexpected/internal fall-through wraps with %w to preserve the chain for
// server-side diagnosis.
func mapContentTransitionErr(err error, idStr, op, requirement string) error {
	if errors.Is(err, content.ErrNotFound) {
		return fmt.Errorf("content %s not found", idStr)
	}
	if errors.Is(err, content.ErrInvalidState) {
		return fmt.Errorf("%s: content %s %s", op, idStr, requirement)
	}
	return fmt.Errorf("%s: %w", op, err)
}

func (s *Server) listContent(ctx context.Context, input *ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	limit := clamp(int(input.Limit), 1, 50, 20)

	var ct *content.Type
	if input.ContentType != nil && *input.ContentType != "" {
		t := content.Type(*input.ContentType)
		ct = &t
	}

	// Fetch with type filter at SQL level, then apply status filter in Go.
	// Over-fetch to compensate for post-fetch filtering.
	fetchLimit := limit
	if input.Status != nil && *input.Status != "" {
		fetchLimit = min(limit*3, 50)
	}
	var projectID *uuid.UUID
	if input.Project != nil && *input.Project != "" {
		projectID = s.resolveProjectID(ctx, *input.Project)
		if projectID == nil {
			// Requested project does not resolve — return empty rather than
			// silently widening to all content. Before this fix the project
			// filter was dropped entirely; honoring it means an unknown
			// project matches nothing, not everything.
			return nil, ManageContentOutput{Contents: []ContentSummary{}, Total: 0, Action: "list"}, nil
		}
	}

	contents, _, err := s.contents.Contents(ctx, content.Filter{
		Page: 1, PerPage: fetchLimit, Type: ct, Project: projectID,
	})
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("listing contents: %w", err)
	}

	summaries := make([]ContentSummary, 0, len(contents))
	for i := range contents {
		c := &contents[i]
		if input.Status != nil && *input.Status != "" && string(c.Status) != *input.Status {
			continue
		}
		summaries = append(summaries, ContentSummary{
			ID:        c.ID.String(),
			Title:     c.Title,
			Type:      string(c.Type),
			Status:    string(c.Status),
			UpdatedAt: c.UpdatedAt.Format(time.RFC3339),
		})
		if len(summaries) >= limit {
			break
		}
	}
	return nil, ManageContentOutput{Contents: summaries, Total: len(summaries), Action: "list"}, nil
}

func (s *Server) readContent(ctx context.Context, input *ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.ContentID == nil || *input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required for read")
	}
	id, err := uuid.Parse(*input.ContentID)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("invalid content_id: %w", err)
	}

	c, err := s.contents.Content(ctx, id)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("reading content: %w", err)
	}

	return nil, ManageContentOutput{Content: toContentDetail(c), Action: "read"}, nil
}

func toContentDetail(c *content.Content) *ContentDetail {
	return &ContentDetail{
		ID:        c.ID.String(),
		Slug:      c.Slug,
		Title:     c.Title,
		Body:      c.Body,
		Excerpt:   c.Excerpt,
		Type:      string(c.Type),
		Status:    string(c.Status),
		Tags:      c.Tags,
		CreatedAt: c.CreatedAt.Format(time.RFC3339),
		UpdatedAt: c.UpdatedAt.Format(time.RFC3339),
	}
}

func toContentSummaries(contents []content.Content) []ContentSummary {
	summaries := make([]ContentSummary, len(contents))
	for i := range contents {
		c := &contents[i]
		summaries[i] = ContentSummary{
			ID:        c.ID.String(),
			Title:     c.Title,
			Type:      string(c.Type),
			Status:    string(c.Status),
			UpdatedAt: c.UpdatedAt.Format(time.RFC3339),
		}
	}
	return summaries
}
