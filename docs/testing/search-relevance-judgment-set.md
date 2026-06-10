# Search-Relevance Judgment Set

> Normalized fixtures for `search_knowledge` relevance evaluation. The loader
> (`internal/mcp/search_test.go`) reads **only the fenced ```yaml blocks** in
> this file — surrounding prose is documentation and is ignored by the parser.

## How this file is consumed

- `TestSearchFixtures_ParseAllBlocks` parses every block and asserts the total
  count, unique ids, required fields, and enum membership.
- `TestSearchFixtures_SelectNegFltOnly` partitions fixtures into the tier-1
  mechanical subset (`NEG-*` and `FLT-*` with `automation_possible: "yes"`) and
  the human-judgment remainder (`KN/LRN/PLAN`).
- The DB-backed tier-1 evaluator (integration suite) runs only the NEG/FLT
  subset and asserts **contract** outcomes (presence / absence / narrowing /
  rejection / empty) — never ranking metrics.

## Field grammar

| Key | Required | Meaning |
|---|---|---|
| `fixture_id` | yes | `^[A-Z][A-Z0-9]{1,3}-\d{2}$` — category prefix + two-digit number |
| `query` | yes | Non-empty query text passed to `search_knowledge` |
| `filters` | yes | Subset of `SearchKnowledgeInput` filters; `{}` for none |
| `seed_requirements` | yes | Corpus rows the fixture assumes exist; `[]` if none |
| `automation_possible` | yes | Quoted string: `"yes"` \| `"no"` \| `"partial"` |
| `expected_outcome` | no | `results` \| `empty` \| `validation_error` \| `judgment` |
| `scenario_category` | no | Human-readable grouping label |
| `date_anchor` | no | Reference date for date-relative fixtures |
| `should_not_appear_criteria` | no | Report-only absence note |
| `notes` | no | Report-only commentary |

Filter keys (mirror `SearchKnowledgeInput`): `source_types` (`content` \| `note`),
`content_type` (`article` \| `essay` \| `build-log` \| `til` \| `digest`),
`note_kind` (`solve-note` \| `concept-note` \| `debug-postmortem` \|
`decision-log` \| `reading-note` \| `musing`), `project` (unsupported — rejected),
`after` / `before` (`YYYY-MM-DD`), `limit` (max 50).

## Coverage summary (28 fixtures)

| Prefix | Count | Tier-1? | Outcome class |
|---|---|---|---|
| `KN` | 5 | no (human judgment) | `judgment` |
| `LRN` | 5 | no (human judgment) | `judgment` |
| `PLAN` | 5 | no (human judgment) | `judgment` |
| `NEG` | 5 | yes (mechanical) | `empty` |
| `FLT` | 8 | yes (mechanical) | `results` / `validation_error` |

---

## KN — knowledge discovery (natural-language relevance, human-judged)

These probe whether seed content / notes surface for a plausible query. The
right ranking is a human call, so they are excluded from the mechanical run.

```yaml
fixture_id: KN-01
scenario_category: knowledge-discovery
query: "value semantics in Go"
filters: {}
seed_requirements:
  - content:article:go-value-vs-pointer-semantics
automation_possible: "no"
expected_outcome: judgment
notes: "Should surface the Go value-semantics article ahead of incidental mentions."
```

```yaml
fixture_id: KN-02
scenario_category: knowledge-discovery
query: "pgvector indexing strategy HNSW"
filters: {}
seed_requirements:
  - content:build-log:pgvector-hnsw-tuning
automation_possible: "no"
expected_outcome: judgment
notes: "Build-log on HNSW tuning is the target; a general embeddings note is acceptable but lower."
```

```yaml
fixture_id: KN-03
scenario_category: knowledge-discovery
query: "how hybrid search merges tsvector and vector results"
filters: {}
seed_requirements:
  - content:article:hybrid-search-rrf
automation_possible: "no"
expected_outcome: judgment
notes: "RRF-merge article is the target; the query is conceptual, not keyword-exact."
```

```yaml
fixture_id: KN-04
scenario_category: knowledge-discovery
query: "graceful shutdown ordering for background goroutines"
filters: {}
seed_requirements:
  - content:til:graceful-shutdown-ordering
automation_possible: "no"
expected_outcome: judgment
should_not_appear_criteria: "Unrelated HTTP-server TILs should not outrank the shutdown TIL."
```

```yaml
fixture_id: KN-05
scenario_category: knowledge-discovery
query: "why I chose pgx over database/sql"
filters: {}
seed_requirements:
  - content:essay:pgx-over-database-sql
automation_possible: "no"
expected_outcome: judgment
notes: "Opinion/decision essay; phrasing is first-person and won't keyword-match exactly."
```

## LRN — learning-domain discovery (human-judged)

```yaml
fixture_id: LRN-01
scenario_category: learning-discovery
query: "DFS termination condition pitfalls"
filters:
  note_kind: solve-note
seed_requirements:
  - note:solve-note:graph-dfs-termination
automation_possible: "no"
expected_outcome: judgment
notes: "Filtered to solve-notes; relevance ordering within the kind is human-judged."
```

```yaml
fixture_id: LRN-02
scenario_category: learning-discovery
query: "dynamic programming state definition vs transition"
filters:
  note_kind: concept-note
seed_requirements:
  - note:concept-note:dp-state-definition
automation_possible: "no"
expected_outcome: judgment
```

```yaml
fixture_id: LRN-03
scenario_category: learning-discovery
query: "binary search off-by-one boundary handling"
filters: {}
seed_requirements:
  - note:solve-note:binary-search-boundaries
automation_possible: "no"
expected_outcome: judgment
```

```yaml
fixture_id: LRN-04
scenario_category: learning-discovery
query: "what I keep getting wrong about sliding window"
filters: {}
seed_requirements:
  - note:debug-postmortem:sliding-window-miss
automation_possible: "no"
expected_outcome: judgment
notes: "Reflective phrasing; should still surface the postmortem note."
```

```yaml
fixture_id: LRN-05
scenario_category: learning-discovery
query: "spaced repetition retention notes"
filters:
  note_kind: reading-note
seed_requirements:
  - note:reading-note:fsrs-retention
automation_possible: "no"
expected_outcome: judgment
```

## PLAN — planning discovery (human-judged)

```yaml
fixture_id: PLAN-01
scenario_category: planning-discovery
query: "Koopa Studio launch plan"
filters: {}
seed_requirements:
  - content:build-log:koopa-studio-kickoff
automation_possible: "no"
expected_outcome: judgment
notes: "search_knowledge covers content/notes only — goals/projects are separate entities; this judges whether written planning content surfaces."
```

```yaml
fixture_id: PLAN-02
scenario_category: planning-discovery
query: "this week's engineering priorities"
filters: {}
seed_requirements:
  - content:digest:weekly-2026-W20
automation_possible: "no"
expected_outcome: judgment
```

```yaml
fixture_id: PLAN-03
scenario_category: planning-discovery
query: "GDE application preparation milestones"
filters: {}
seed_requirements:
  - content:essay:gde-application-prep
automation_possible: "no"
expected_outcome: judgment
```

```yaml
fixture_id: PLAN-04
scenario_category: planning-discovery
query: "content production cadence target"
filters: {}
seed_requirements:
  - content:essay:content-cadence
automation_possible: "no"
expected_outcome: judgment
```

```yaml
fixture_id: PLAN-05
scenario_category: planning-discovery
query: "retrospective on deferred work"
filters: {}
seed_requirements:
  - content:essay:deferred-work-retro
automation_possible: "no"
expected_outcome: judgment
should_not_appear_criteria: "Generic build-logs without a retrospective framing should rank below the retro essay."
```

## NEG — negative controls (mechanical: must return empty)

Nonsense tokens with no tsvector lexeme and no plausible vector neighbour.
They return zero results independent of corpus contents.

```yaml
fixture_id: NEG-01
scenario_category: negative-control
query: "zqxwvut nonexistent corpus token"
filters: {}
seed_requirements: []
automation_possible: "yes"
expected_outcome: empty
notes: "No lexeme match, no semantic neighbour — empty regardless of seed data."
```

```yaml
fixture_id: NEG-02
scenario_category: negative-control
query: "blarghfizzbuzz unmatched gibberish"
filters: {}
seed_requirements: []
automation_possible: "yes"
expected_outcome: empty
```

```yaml
fixture_id: NEG-03
scenario_category: negative-control
query: "qwizzlefrobnicator wuzzle"
filters: {}
seed_requirements: []
automation_possible: "yes"
expected_outcome: empty
```

```yaml
fixture_id: NEG-04
scenario_category: negative-control
query: "xyzzy plugh floop snork"
filters: {}
seed_requirements: []
automation_possible: "yes"
expected_outcome: empty
```

```yaml
fixture_id: NEG-05
scenario_category: negative-control
query: "vorpalsnark jabberwock brillig"
filters: {}
seed_requirements: []
automation_possible: "yes"
expected_outcome: empty
```

## FLT — filter controls (mechanical: narrowing or rejection)

Each fixture exercises one filter mechanism. `results` fixtures assert the
filter narrows the corpus; `validation_error` fixtures assert the validator
rejects the input before any store call.

```yaml
fixture_id: FLT-01
scenario_category: filter-content-type
query: "go"
filters:
  content_type: article
seed_requirements:
  - content:article:any
  - content:til:any
  - note:solve-note:any
automation_possible: "yes"
expected_outcome: results
should_not_appear_criteria: "No note rows; no content rows whose type != article."
notes: "content_type=article implies source_types=[content]; notes excluded automatically."
```

```yaml
fixture_id: FLT-02
scenario_category: filter-content-type
query: "go"
filters:
  content_type: til
seed_requirements:
  - content:til:any
  - content:article:any
automation_possible: "yes"
expected_outcome: results
should_not_appear_criteria: "No article/essay/build-log/digest rows; no notes."
```

```yaml
fixture_id: FLT-03
scenario_category: filter-note-kind
query: "go"
filters:
  note_kind: solve-note
seed_requirements:
  - note:solve-note:any
  - content:article:any
automation_possible: "yes"
expected_outcome: results
should_not_appear_criteria: "No content rows; no notes whose kind != solve-note."
notes: "note_kind=solve-note implies source_types=[note]; content excluded automatically."
```

```yaml
fixture_id: FLT-04
scenario_category: filter-source-types
query: "go"
filters:
  source_types:
    - content
seed_requirements:
  - content:article:any
  - note:concept-note:any
automation_possible: "yes"
expected_outcome: results
should_not_appear_criteria: "No note rows in the result set."
```

```yaml
fixture_id: FLT-05
scenario_category: filter-date-range
query: "go"
date_anchor: "2026-03-31"
filters:
  after: "2026-01-01"
  before: "2026-03-31"
seed_requirements:
  - content:article:dated-2026-02-15
  - content:article:dated-2025-12-01
automation_possible: "yes"
expected_outcome: results
should_not_appear_criteria: "Rows created before 2026-01-01 or after 2026-03-31 (inclusive day bounds)."
```

```yaml
fixture_id: FLT-06
scenario_category: filter-limit
query: "go"
filters:
  limit: 5
seed_requirements:
  - content:article:bulk-10-plus
automation_possible: "yes"
expected_outcome: results
notes: "With more than 5 matching rows, the result set is capped at 5."
```

```yaml
fixture_id: FLT-07
scenario_category: filter-validation
query: "go"
filters:
  content_type: article
  note_kind: solve-note
seed_requirements: []
automation_possible: "yes"
expected_outcome: validation_error
notes: "content_type and note_kind are mutually exclusive; rejected before any store call."
```

```yaml
fixture_id: FLT-08
scenario_category: filter-validation
query: "go"
filters:
  project: koopa
seed_requirements: []
automation_possible: "yes"
expected_outcome: validation_error
notes: "project is an unsupported filter; a non-empty value is rejected as unsupported_filter."
```
