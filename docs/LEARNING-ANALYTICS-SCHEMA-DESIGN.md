# Learning Analytics Schema Extension — Design Record

**Date**: 2026-04-04
**Status**: DDL integrated into `001_initial.up.sql`
**Reviewers**: Koopa (owner + adjudicator), Claude (Opus), ChatGPT, Gemini
**Implementation**: Claude Code (Opus 4.6)
**Scope**: 7 new tables, 1 existing table modified (review_cards: unified FSRS target)

---

## 1. Context and Motivation

The koopa0.dev PostgreSQL schema (v2, signed off 2026-04-04) implements PARA + GTD, a Knowledge Engine, a Retrieval Substrate (FSRS), and an IPC Protocol. It handles "what I learned" (notes, contents) and "when to review" (review_cards). It cannot answer:

- **Why am I weak at binary search?** — No concept-level weakness tracking.
- **Which attempts support that judgment?** — No attempt history.
- **What should I practice next?** — No variation/prerequisite graph.
- **Is my weakness improving or regressing?** — No temporal signal tracking.

The Learning Analytics Engine fills this gap with 7 new tables that provide attempt tracking, concept ontology, weakness diagnosis, and variation-aware recommendation.

### What This Is

The Learning Engine is an **Area-level capability** under `areas.slug = 'continuous-learning'`. It is permanent infrastructure, not a PARA project. Specific learning sprints ("JLPT N3 合格", "binary-search weakness convergence") are PARA projects or goals that the engine serves.

### What This Is Not

- Not an OKR or quantitative mastery scoring system. Mastery is derived from discrete signals, not numeric scores.
- Not a replacement for FSRS. Review cards handle "when to review" (scheduling). Learning analytics handles "how well you understand" (diagnosis).
- Not a multi-user system. Personal scale — no participant column on learning tables.

---

## 2. Design Review Process

Three independent AI reviewers (Claude Opus, ChatGPT, Gemini) produced initial designs. Koopa performed convergence review, resolving all disagreements with explicit rationale. Claude Code (Opus 4.6) then reviewed the converged design for implementation correctness, raised 7 challenges (all resolved), and produced the DDL.

### Disagreements Resolved by Adjudication

| Question | Claude | ChatGPT | Gemini | Ruling | Rationale |
|----------|--------|---------|--------|--------|-----------|
| learning_items independent from notes? | Yes | Yes | No (use notes as anchor) | Independent | Different lifecycles: notes = knowledge maturity, items = learning progress. Items exist before notes. |
| concept_mastery snapshot table? | No | No | Yes | No | Derived state from observations. Two sources of truth = consistency nightmare. Materialized view if needed. |
| learning_sessions independent from journal? | No | Yes | No | Independent, lightweight | Session = orchestration boundary (start/end/mode). Journal = post-hoc reflection. Different entities. |
| learning_tracks table? | No | Yes | No | No | Domain as TEXT field sufficient. Tracks have no independent lifecycle. |
| review_cards extension approach? | Nullable FK on existing table | Separate table | N/A | Nullable FK (Phase 2) | Avoids duplicating FSRS state logic. |
| concepts.kind values? | pattern/skill/knowledge | pattern/skill/knowledge | pattern/skill/knowledge | pattern/skill/**principle** | "knowledge" overlaps with notes. "principle" is sharper: theoretical foundation. |
| Naming prefix? | Mixed | learning_ prefix | Mixed | No prefix except learning_items, learning_sessions | Consistency with existing schema (notes, tasks, contents). `items` and `sessions` too generic without prefix. |

---

## 3. Technical Decisions

### 3.1 Concepts Independent from Tags

**Decision**: New `concepts` table. Do not overload `tags`.

**Rationale**: Tags handle canonical labeling, search, and content classification. Concepts need hierarchy (parent_id), domain awareness, kind classification, and mastery tracking. Optional `tag_id` FK bridges them when both exist for the same thing.

**Boundary rule**: Not all tags are concepts. Not all concepts have tags.

### 3.2 Learning Items Independent from Notes

**Decision**: New `learning_items` table. `note_id` is optional FK.

**Rationale**: A LeetCode problem exists before you write a solve note. Lifecycles differ: notes = seed → evergreen → archived; items = not-attempted → practicing → mastered. If notes were the anchor, "items I should attempt but haven't" would have no place.

**Backfill note**: Existing `notes` with `leetcode_id`, `difficulty`, `book`, `chapter` contain learning item identity data. A one-time backfill should create corresponding `learning_items` rows and set the `note_id` FK.

### 3.3 Learning Sessions Separate from Journal

**Decision**: New lightweight `learning_sessions` table. `journal_id` is optional FK.

**Rationale**: Sessions have explicit start/end and mode (retrieval/practice/mixed/review/reading). Journal is post-hoc reflection (plan/context/reflection/metrics). A session ending may produce a journal entry, but they are different entities. Without a session table, "how many sessions this week, average duration, breakdown by mode" requires scanning journal JSONB.

### 3.4 Mastery as Derived State

**Decision**: No `concept_mastery` table. Compute from `attempt_observations` aggregation.

**Rationale**: Stored snapshot + computed aggregate = two sources of truth. At personal scale, aggregation queries are fast. Use materialized view if performance becomes an issue (unlikely).

### 3.5 Outcome Enum — Two Paradigms

**Decision**: `attempts.outcome` has 7 values covering both problem-solving and immersive learning.

**Rationale**: The original design (5 values: `solved_independent`, `solved_with_hint`, `solved_after_solution`, `incomplete`, `gave_up`) was biased toward problem-solving. Reading DDIA, 精讀太宰治, or listening to ヨルシカ cannot be described as "solved." Two values added:

| Value | Paradigm | When |
|-------|----------|------|
| `solved_independent` | Problem-solving | LeetCode, grammar drills — no help |
| `solved_with_hint` | Problem-solving | Needed a nudge |
| `solved_after_solution` | Problem-solving | Understood only after seeing answer |
| `completed` | Immersive | Finished reading/listening/review independently |
| `completed_with_support` | Immersive | Finished with dictionary, subtitles, translation, Claude annotation |
| `incomplete` | Shared | Partially done (either paradigm) |
| `gave_up` | Shared | Could not proceed (either paradigm) |

MCP tool layer maps domain context to the appropriate paradigm. This is a design trade-off, not a defect — the model's center of gravity is problem-solving, and immersive learning gets semantic coverage through the two new values plus tool-layer adaptation.

### 3.6 Domain as Go-Validated TEXT with Format Guard

**Decision**: `domain` fields on concepts, learning_items, learning_sessions have no value-set CHECK constraint. However, all three tables enforce a format guard: `CHECK (domain = lower(btrim(domain)) AND domain <> '')` — prevents casing/whitespace drift that would fragment analytics.

**Rationale**: Domain set is open-ended (leetcode, japanese, system-design, go, english, reading, and future additions). DB-level value CHECK would require `ALTER TABLE ... DROP CONSTRAINT ... ADD CONSTRAINT` for every new domain. Go-layer validation provides equivalent safety with more flexibility for the value set. The format guard is a DB-level complement — it ensures consistency without constraining the vocabulary. Same reasoning applies to `attempt_observations.category` (Go-validated, no DB format guard needed since it's always written by the same MCP tool codepath).

**Deviation acknowledged**: schema-design.md says "MUST use TEXT column with CHECK constraint" for enum patterns. This is a deliberate deviation for cross-domain fields that expand frequently. The format guard is a pragmatic middle ground.

### 3.7 No Learning Tracks Table

**Decision**: Use `domain` TEXT field for domain filtering. No `learning_tracks` entity.

**Rationale**: A "track" has no independent lifecycle. "Pausing Japanese study" means stopping new attempts, not flipping a track status. If track-level configuration is needed, it belongs in `participant_schedules`.

### 3.8 concepts.slug Uniqueness (Per-Domain)

**Decision**: No column-level UNIQUE. Case-insensitive uniqueness **per domain** via `CREATE UNIQUE INDEX idx_concepts_domain_slug ON concepts (domain, LOWER(slug))`.

**Rationale**: The design document originally specified both `slug TEXT UNIQUE` and a `LOWER(slug)` index. These conflict — column UNIQUE is case-sensitive, functional index is case-insensitive. Dropped column UNIQUE in favor of the stricter functional index. Post-review correction: global uniqueness was wrong — `binary-search` as a leetcode pattern and as a system-design principle are different concepts in different domains and must coexist. Changed to per-domain uniqueness.

### 3.9 Cascade Semantics

| FK | Cascade | Rationale |
|----|---------|-----------|
| `concepts.parent_id → concepts` | SET NULL | Children become roots on parent deletion |
| `concepts.tag_id → tags` | SET NULL | Tag deletion doesn't destroy concept |
| `learning_items.note_id → notes` | SET NULL | Item persists without its note |
| `learning_items.content_id → contents` | SET NULL | Item persists without content |
| `learning_items.project_id → projects` | SET NULL | Item persists without project |
| `learning_item_concepts → learning_items` | CASCADE | Junction row dies with item |
| `learning_item_concepts → concepts` | CASCADE | Junction row dies with concept |
| `learning_sessions.journal_id → journal` | SET NULL | Session persists without reflection |
| `learning_sessions.daily_plan_item_id → daily_plan_items` | SET NULL | Session persists without plan item |
| `attempts.learning_item_id → learning_items` | CASCADE | Attempts die with item |
| `attempts.session_id → learning_sessions` | SET NULL | Attempt persists without session |
| `attempts.note_id → notes` | SET NULL | Attempt persists without working note |
| `attempt_observations.attempt_id → attempts` | CASCADE | Observations die with attempt |
| `attempt_observations.concept_id → concepts` | RESTRICT | Cannot delete a concept that has observations. Merge first: UPDATE observations to surviving concept, then DELETE old concept. Observations are irreplaceable historical analytics — silent deletion is unacceptable. |
| `item_relations.source_item_id → learning_items` | CASCADE | Relation dies with item |
| `item_relations.target_item_id → learning_items` | CASCADE | Relation dies with item |
| `review_cards.learning_item_id → learning_items` | CASCADE | Review card dies with item |

Rule: CASCADE for child/junction tables. SET NULL for optional cross-references.

---

## 4. Implementation Challenges Raised by Claude Code

### 4.1 Partial Unique Index Syntax

The design document specified `UNIQUE (domain, external_id) WHERE external_id IS NOT NULL` as a table constraint. PostgreSQL does not support `WHERE` on table-level UNIQUE constraints. Implemented as `CREATE UNIQUE INDEX idx_learning_items_domain_external ON learning_items (domain, external_id) WHERE external_id IS NOT NULL`.

### 4.2 item_relations Direction Semantics

Direction was implicit in the design document. Made explicit in table and column comments: **source is the reference point, target is the related item, relation_type describes how target relates to source.** Example: `(source=42, target=167, easier_variant)` means "167 is an easier variant of 42."

### 4.3 Learning Sessions Without Participant

The IPC model consistently tracks authorship (`journal.source`, `insights.source`, `tasks.created_by`). `learning_sessions` has no participant column. Acceptable at personal scale — participant is traceable via `journal_id → journal.source`. Documented in table comment for future migration if needed.

### 4.4 attempt_observations.severity — Weakness Only

`severity` (minor/moderate/critical) applies naturally to `weakness` signals but is awkward for `improvement`/`mastery`. DDL-enforced: `CONSTRAINT chk_severity_weakness_only CHECK (signal_type = 'weakness' OR severity IS NULL)`. Non-weakness signals must have NULL severity.

### 4.5 attempts.attempt_number Concurrency

With `UNIQUE (learning_item_id, attempt_number)`, the application must compute `MAX(attempt_number) + 1` before inserting. Theoretical race condition if two sessions insert attempts for the same item simultaneously. Negligible at personal scale. Documented in column comment.

---

## 5. What NOT to Build (Explicit Non-Goals)

| Not Building | Rationale |
|-------------|-----------|
| `learning_tracks` table | Domain as TEXT field sufficient. No independent lifecycle. See §5.1 for upgrade path. |
| `concept_mastery` / snapshots | Derived state. Two sources of truth = consistency nightmare. |
| `kind/type` on `projects` | Pollutes PARA project semantics. |
| Per-coaching-hint normalization | Narrative data stays in JSONB. |
| Numeric mastery scoring algorithm | Discrete signals via observations. Scores can be derived later. |

### 5.1 Domain → Track Promotion Trigger

Not building `learning_tracks` now is correct. But "not now" must not be misread as "never." Following the project's upgrade path convention (cf. `sources` table comment: "when a second provider is added for the same role..."):

> **Promotion trigger**: When the same `domain` value requires multiple distinguishable learning contexts with independent query scope, independent UI, or independent scheduling (e.g., `japanese/grammar-rehab` vs `japanese/N3-sprint`), promote `domain` to a first-class `learning_tracks` or `study_contexts` entity. Until then, `domain` as TEXT field is sufficient.

### 5.2 Review Cards — Unified Table (Phase 1 Decision)

**Phase 1 (implemented)**: Option B (unified table) was chosen for the initial schema:
- `content_id` changed from `NOT NULL` to nullable
- `learning_item_id UUID` column added (FK via ALTER TABLE after learning_items exists)
- `chk_review_target_exactly_one CHECK (num_nonnulls(content_id, learning_item_id) = 1)` — exactly one target
- `chk_tag_requires_content CHECK (tag_id IS NULL OR content_id IS NOT NULL)` — tag dimension only for content cards
- Content-based indexes rewritten with `WHERE content_id IS NOT NULL` qualifier
- New `idx_review_cards_item` for learning-item-based cards
- Table relocated after `learning_items` in DDL so both FK targets exist at definition time (no ALTER TABLE needed)
- FSRS engine Go code unchanged — it only touches card_state, due, and rating

**Rationale**: FSRS is target-agnostic — it operates on `(card_state, rating) → new_card_state` regardless of what the card represents. The rating scale (1-4), card_state lifecycle (New → Learning → Review → Relearning), and scheduling algorithm are identical for content-based and item-based review.

**Phase 2 concern — not "just add a column"**: The review target identity model is a non-trivial design surface. If the unified table proves problematic (e.g., query complexity from polymorphic target, index bloat from partial indexes, or future target types beyond content/item), there are two migration paths:
- **Option A**: Separate `learning_review_cards` table — clean boundary but duplicates FSRS state logic.
- **Option B**: Formal refactor of `review_cards` into a polymorphic target model — single FSRS engine but complex partial indexes and CHECK constraints.

Either path is a full schema migration, not a one-column addition. Do not underestimate the scope when planning Phase 2.

---

## 6. Responsibility Boundaries

| Entity | Responsibility | Does NOT Handle |
|--------|---------------|-----------------|
| `notes` | Knowledge artifacts, study notes | Attempt tracking, mastery, weakness |
| `contents` | Published output | Learning analytics |
| `tags` | Canonical labeling, search, classification | Learning ontology, mastery tracking |
| `review_cards` | FSRS scheduling ("when to review") | Mastery diagnosis ("how well you understand") |
| `concepts` | Learning ontology, mastery tracking | Content classification, search labeling |
| `learning_items` | Learning targets ("what to learn") | Knowledge storage, content publishing |
| `attempts` | Behavioral records ("what happened") | Knowledge artifacts, scheduling |
| `attempt_observations` | Micro-cognitive signals | Coaching transcripts, narratives |
| `learning_sessions` | Orchestration boundaries | Post-hoc reflection (that's `journal`) |
| `journal` | Post-hoc reflection | Session orchestration, attempt tracking |

---

## 7. Cross-Domain Coverage

| Domain | learning_items | concepts | attempts.outcome paradigm |
|--------|---------------|----------|--------------------------|
| LeetCode | One per problem (external_id = number) | Patterns + skills | Problem-solving |
| Japanese | Grammar drills, listening clips, vocab | Grammar rules, skills | Mixed (drills = problem-solving, reading/listening = immersive) |
| System Design | Design prompts, case studies | Patterns + skills | Problem-solving |
| Reading (DDIA, literary) | Chapters, sections, passages | Principles + skills | Immersive |
| Listening (songs, podcasts) | Clips, episodes | Skills | Immersive |

---

## 8. Key Queries the Schema Supports

### Weakness Overview (Dashboard)
```sql
SELECT c.name, c.domain, c.kind,
       COUNT(*) FILTER (WHERE ao.signal_type = 'weakness') AS weakness_count,
       COUNT(*) FILTER (WHERE ao.signal_type = 'improvement') AS improvement_count
FROM concepts c
JOIN attempt_observations ao ON ao.concept_id = c.id
JOIN attempts a ON a.id = ao.attempt_id
GROUP BY c.id
HAVING COUNT(*) FILTER (WHERE ao.signal_type = 'weakness') > 0
ORDER BY weakness_count DESC;
```

### Drill-Down (Items Supporting a Weakness)
```sql
SELECT li.title, a.outcome, a.attempted_at, ao.category, ao.severity, ao.detail
FROM attempt_observations ao
JOIN attempts a ON a.id = ao.attempt_id
JOIN learning_items li ON li.id = a.learning_item_id
WHERE ao.concept_id = :concept_id
ORDER BY a.attempted_at DESC;
```

### Progression Over Time
```sql
SELECT date_trunc('week', a.attempted_at) AS week,
       COUNT(*) FILTER (WHERE ao.signal_type = 'weakness') AS weaknesses,
       COUNT(*) FILTER (WHERE ao.signal_type = 'improvement') AS improvements
FROM attempt_observations ao
JOIN attempts a ON a.id = ao.attempt_id
WHERE ao.concept_id = :concept_id
GROUP BY 1 ORDER BY 1;
```

### Variation Recommendation
```sql
SELECT li.title, li.difficulty, ir.relation_type
FROM item_relations ir
JOIN learning_items li ON li.id = ir.target_item_id
WHERE ir.source_item_id = :item_id
  AND ir.relation_type IN ('easier_variant', 'same_pattern')
ORDER BY li.difficulty;
```

All queries use index joins on first-class columns. No JSONB extraction needed.

---

## 9. Phased Implementation

### Phase 1 — Now (This Migration)
- 7 tables in `001_initial.up.sql`
- Wire `log_learning_session` MCP tool to write attempts + observations
- Backfill existing notes with `leetcode_id` into learning_items
- **Critical path**: coaching prompt observation quality, not UI. Validate with 10-20 real LeetCode sessions. Manually verify each weakness signal written to `attempt_observations` is accurate.

### Phase 2 — LeetCode Strengthening
- Build concept hierarchy for LeetCode domain (populate parent_id relationships)
- Populate `item_relations` via coaching prompt post-session analysis (see §9.1), not manual backfill

### Phase 3 — Multi-Domain Expansion
- Define concept taxonomies for Japanese, System Design, Reading
- Expand `attempt_observations.category` vocabulary via Go validation
- No new tables needed — Phase 1 structure is domain-agnostic

### 9.1 item_relations Population Strategy

`item_relations` will appear dead if treated as a manual data entry table. The natural population time is **post-session analysis**, not manual curation or backfill scripts.

Concrete flow: after a session ends and `attempt_observations` are written, the coaching prompt's post-session analysis phase should:

1. Observe a weakness signal (e.g., `weakness: edge-cases` on problem 42)
2. Query `learning_item_concepts` for items sharing the same primary concept as problem 42
3. Filter by difficulty (find easier items for the same pattern)
4. Suggest in session summary: "problem 167 is `same_pattern` with `difficulty = easy`, consider as `easier_variant`"
5. Write the suggested relation to `item_relations` (with user confirmation or auto-approve based on confidence)

This means: `item_relations` population logic belongs in the coaching prompt's post-session analysis section, not in a standalone backfill tool. The table schema does not change — only the MCP tool design and coaching prompt structure must account for this flow.

---

## 10. Schema Statistics After Extension

| Metric | Before | After |
|--------|--------|-------|
| Tables | 39 | 46 |
| New tables | — | 7 (concepts, learning_items, learning_item_concepts, learning_sessions, attempts, attempt_observations, item_relations) |
| Existing tables modified | — | 1 (review_cards: content_id nullable, learning_item_id added, one-of CHECK, relocated after learning_items) |
| New indexes in learning analytics section | — | 30 (includes review_cards/review_logs relocated indexes) |
| New CHECK constraints | — | 7 named (chk_attempt_number_positive, chk_duration_positive, chk_review_target_exactly_one, chk_tag_requires_content, chk_session_time_order, chk_severity_weakness_only, chk_no_self_relation) + inline CHECKs (domain format guards, kind, outcome, relevance, session_mode, difficulty, signal_type, severity values) |
