// content.go contains the internal workhorses behind the flat content
// MCP tools declared in content_tools.go. It defines the shared
// ManageContentInput shape, the per-transition internal methods
// (createContent, updateContent, publishContent, …), and the
// publish-authority guard (publish requires an explicit `as: "human"`).
//
// Why the split: the MCP surface is flat, but the internal logic
// branches on the transition being requested. Keeping the branch logic
// here (one file) instead of spreading it across eight handlers keeps
// the publish-authority and state-machine rules in one reviewable place.

package mcp

import (
	"context"
	"errors"
	"fmt"
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
	// Matches the content_status enum. The 'review' state was reinstated in
	// schema cleanup as Claude → human publish handoff signal.
	validStatuses = map[string]struct{}{
		"draft":     {},
		"review":    {},
		"published": {},
		"archived":  {},
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

type ManageContentOutput struct {
	Content         *ContentDetail    `json:"content,omitempty"`
	Contents        []ContentSummary  `json:"contents,omitempty"`
	Action          string            `json:"action"`
	ContentWarnings []string          `json:"content_warnings"`
	SlugConflict    *SlugConflictInfo `json:"slug_conflict,omitempty"`
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
	if input.Status != nil && *input.Status != "" {
		if _, ok := validStatuses[*input.Status]; !ok {
			return fmt.Errorf("invalid status %q (one of: draft, review, published, archived)", *input.Status)
		}
	}
	if input.NoteKind != nil && *input.NoteKind != "" {
		return fmt.Errorf("note_kind is not a content field — notes are a separate entity. Use manage_note")
	}
	if input.Maturity != nil && *input.Maturity != "" {
		return fmt.Errorf("maturity is not a content field — notes are a separate entity. Use manage_note")
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

// createContent is intentionally open to all callers — any agent (and
// any caller without `as`, falling back to the server default) may
// draft a content row in status=draft. The editorial pipeline gates
// the dangerous transition (review → published) at publish_content,
// not at create. Front-end review and human curation handle quality;
// the create surface trusts the writer because every draft is private
// until publish.
func (s *Server) createContent(ctx context.Context, input *ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if err := validateCreateContentFields(input); err != nil {
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
			Slug:      deriveCreateSlug(input),
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

	var st *content.Status
	if input.Status != nil && *input.Status != "" {
		cs := content.Status(*input.Status)
		st = &cs
	}

	var c *content.Content
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		c, err = content.NewStore(tx).UpdateContent(ctx, id, &content.UpdateParams{
			Title:  input.Title,
			Body:   input.Body,
			Type:   ct,
			Status: st,
			Slug:   input.Slug,
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

	// Publishing transitions content from review → published, which is
	// a human-only act per the editorial lifecycle (agent drafts and
	// submits for review; human publishes). See authz.go for why
	// requireExplicitHuman refuses the server default rather than
	// accepting it.
	if err := s.requireExplicitHuman(ctx, "publish_content"); err != nil {
		return nil, ManageContentOutput{}, err
	}
	_, callerName := s.ExplicitCallerIdentity(ctx)

	var c *content.Content
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		c, err = content.NewStore(tx).PublishContent(ctx, id)
		return err
	})
	if err != nil {
		if errors.Is(err, content.ErrNotFound) {
			return nil, ManageContentOutput{}, fmt.Errorf("content %s not found", id)
		}
		return nil, ManageContentOutput{}, fmt.Errorf("publishing content: %w", err)
	}

	s.logger.Info("manage_content", "action", "publish", "id", c.ID, "caller", callerName)
	return nil, ManageContentOutput{Content: toContentDetail(c), Action: "publish"}, nil
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
	contents, _, err := s.contents.Contents(ctx, content.Filter{
		Page: 1, PerPage: fetchLimit, Type: ct,
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
	return nil, ManageContentOutput{Contents: summaries, Action: "list"}, nil
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
