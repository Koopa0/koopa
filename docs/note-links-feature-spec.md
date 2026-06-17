# Feature Spec — Note ↔ Concept/Target Link Editing (admin)

Goal: let the admin note editor add/remove a note's linked **concepts** and
**learning targets**, persisting them through the HTTP API. Today the editor
sends the links but nothing persists them — this spec is the complete write
path plus the picker UX it needs.

## Current state (verified)

- `internal/note/store.go` has `AttachConcept` / `DetachConcept` /
  `ConceptsForNote`, but **`AttachConcept` is never called by any path** (not
  HTTP, not MCP) — note-link writing was never wired. There is **no**
  `AttachTarget` / `DetachTarget`.
- `internal/note/handler.go`:
  - `createRequest` (≈line 135) declares `concept_slugs` + `target_ids`
    "for parity with the MCP create_note shape", and the doc comment says the
    HTTP path **does not** resolve them.
  - `updateRequest = UpdateParams` (≈line 194); `UpdateParams`
    (`internal/note/note.go`) is `slug/title/body/kind/metadata` only — no
    links.
- Frontend `note-editor.page.ts`: link fields are **CSV text inputs** —
  `conceptSlugs` (CSV of slugs) and `targetIds` (CSV of UUIDs). On save it
  sends `concept_slugs` + `target_ids` (`note.service.ts` `NoteUpdateRequest`).
  **These silently fail** (handler drops them).
- Read side: `ConceptRefsForNote` returns `{slug, name}` (no id);
  `TargetRefsForNote` returns `{id, title}` via the `learning_target_notes`
  junction.

## Data-model constraints (the reason this isn't a 1-liner)

- `concepts` are unique by **(domain, LOWER(slug))** — `idx_concepts_domain_slug`.
  `ConceptBySlug(ctx, domain, slug)` REQUIRES a domain. A note can link concepts
  across domains, so **a bare slug cannot resolve to one concept id**. The write
  path MUST take concept **IDs**, not slugs.
- Targets already flow as IDs (`learning_target_notes` junction;
  write queries exist in `internal/learning/query.sql` ≈647 INSERT / 654 DELETE
  — but in the *learning* package, not note).
- `note_concepts` has a partial unique index `idx_note_concepts_one_primary`
  (≤1 primary per note); `AttachConcept` takes a `relevance` arg.

## Design decisions

1. **IDs, not slugs.** Change the wire to `concept_ids: uuid[]` and
   `target_ids: uuid[]`. Drop `concept_slugs` from the note update path.
2. **Read side exposes ids.** Add `id` to the note `ConceptRef` so the editor
   can round-trip selections. (Targets already expose `id`.)
3. **Set-semantics, transactional.** `concept_ids == nil` ⇒ leave links
   untouched; `[]` ⇒ clear all. Diff against `ConceptsForNote` /
   targets-for-note, attach added / detach removed, all inside the request
   actor-tx (`mustAdminTx`).
4. **Picker, not CSV.** Replace both CSV inputs with a real
   search-select-chips picker (none exists in `shared/` yet — build a reusable
   one). Concepts feed from `GET /api/admin/learning/concepts`; targets need a
   **new** list endpoint (only `targets/{id}/attempts` exists today).

## Implementation plan

### Backend (Go — sqlc/store/handler + integration test)
1. `note/query.sql`: add `AddNoteTarget` / `DeleteNoteTarget` (INSERT/DELETE on
   `learning_target_notes`) + a `TargetsForNote :many` (current target ids).
   `sqlc generate`.
2. `note/store.go`: `AttachTarget` / `DetachTarget` / `TargetsForNote`;
   `SetConcepts(noteID, ids)` and `SetTargets(noteID, ids)` that diff and
   attach/detach. Validate concept/target ids exist (FK will error otherwise —
   map to `ErrInvalidInput`).
3. `note/note.go` `UpdateParams`: add `ConceptIDs *[]uuid.UUID`,
   `TargetIDs *[]uuid.UUID` (pointer = "untouched" vs `[]` = "clear").
4. `note/handler.go` `Update`: within `mustAdminTx`, after `store.Update`, call
   `SetConcepts` / `SetTargets` when the slices are non-nil.
5. New endpoint `GET /api/admin/learning/targets` (list, for the picker) in
   `internal/learning` + route in `cmd/app/routes.go`.
6. Add `id` to `ConceptRefsForNote` projection (query + `ConceptRef`).
7. Integration test (testcontainers): create note → PUT concept_ids/target_ids →
   assert junctions; clear with `[]`; FK-violation on bad id → 400/422.

### Frontend (Angular — picker + wire)
1. `shared/components/entity-picker/` — reusable search-select-chips
   (input → debounced search → results → chips with remove). OnPush, signals,
   `data-testid`s, spec.
2. `note.model` / `note.service`: `NoteUpdateRequest` → `concept_ids` +
   `target_ids` (drop `concept_slugs`); note read `concepts: {id,slug,name}[]`.
3. `note-editor.page`: replace the two CSV `FormControl`s with the picker
   (concepts via `/learning/concepts`, targets via the new list endpoint),
   seed from the loaded note, emit ids on save.
4. Specs: editor spec asserts the PUT body carries `concept_ids` / `target_ids`;
   picker component spec.

## Acceptance criteria

- Editing a note's concepts/targets in the admin editor persists (junction rows
  change); reload shows the edit.
- Clearing all links (`[]`) removes them; leaving the picker untouched (`nil`)
  preserves them.
- Bad id → 400/422, not 500.
- `go build/vet`, `golangci-lint`, `go test` (incl. `-tags=integration`) green;
  frontend `tsc` / `ng lint` / `ng test` / `ng build` green.
- New specs guard both the wire (PUT body) and the picker.

## Out of scope
- Concept *creation* from the editor (stays admin/MCP). Primary-concept
  relevance UI (keep `AttachConcept`'s default relevance).
