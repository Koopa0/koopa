-- Track C: synthesis as historical observation layer (minimum viable slice).
--
-- Purpose:
--   koopa has no record of what derived views looked like at past moments.
--   Primary entities (tasks, goals, attempts) are append-only, but derived
--   views (weekly_summary aggregates, goal_progress percentages, project
--   health scores) are recomputed fresh each time and their past values
--   are lost. You cannot ask "how did this week look six weeks ago" because
--   nobody ever stored the answer.
--
--   syntheses is an append-only historical log of derived-view snapshots,
--   written by a secondary consolidation process (not by live handlers),
--   read by retrospective query tools. It is NOT a cache: the reader never
--   falls through to live compute, there is no TTL, old rows are never
--   overwritten, and primary state remains authoritative.
--
-- Scope of this migration:
--   First vertical slice — only subject_type='week' and kind='weekly_review'
--   are allowed. The CHECK constraints can be extended via ALTER when
--   future slices add goal/project/concept subjects. No consolidation_runs
--   table yet; computed_by label records the writer source. That table
--   arrives in Wave 3 if and when a real orchestration layer is needed.

CREATE TABLE syntheses (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_type  TEXT NOT NULL
        CHECK (subject_type IN ('week')),
    subject_id    UUID,
    subject_key   TEXT,
    kind          TEXT NOT NULL
        CHECK (kind IN ('weekly_review')),
    body          JSONB NOT NULL,
    evidence      JSONB NOT NULL,
    evidence_hash TEXT NOT NULL,
    computed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    computed_by   TEXT NOT NULL,

    CONSTRAINT chk_syntheses_subject_identity
        CHECK (subject_id IS NOT NULL OR subject_key IS NOT NULL)
);

COMMENT ON TABLE syntheses IS 'Append-only historical observation layer. Each row is a frozen snapshot of what a derived view (weekly_review, etc.) looked like at computed_at, based on the evidence set captured in evidence. Never updated after insert. Never invalidated by TTL. Never written by live handlers — only by secondary consolidation processes. Readers get historical state, never current state.';

COMMENT ON COLUMN syntheses.subject_type IS 'What kind of entity this synthesis describes. First slice allows only "week"; future slices extend via ALTER TABLE to add "goal", "project", "concept".';
COMMENT ON COLUMN syntheses.subject_id IS 'UUID subject identity for entity-based subjects (goal, project, concept in future slices). NULL when subject uses a string key (e.g. week). chk_syntheses_subject_identity requires at least one of subject_id or subject_key to be set.';
COMMENT ON COLUMN syntheses.subject_key IS 'String subject identity for time-bucket subjects like week (ISO week key e.g. "2026-W15"). NULL when subject uses a UUID. chk_syntheses_subject_identity requires at least one of subject_id or subject_key to be set.';
COMMENT ON COLUMN syntheses.kind IS 'Which view this synthesis captures. First slice allows only "weekly_review"; future slices extend via ALTER TABLE. A (subject_type, kind) pair determines the body schema.';
COMMENT ON COLUMN syntheses.body IS 'Structured snapshot payload. Shape is determined by kind — for weekly_review the Go type is synthesis.WeeklyReviewBody. NEVER a free-text LLM dump. Always a typed Go struct marshaled to JSON.';
COMMENT ON COLUMN syntheses.evidence IS 'Reference list of primary-state ids that contributed to this snapshot. Shape: [{"type": "task", "id": "..."}, {"type": "session", "id": "..."}, ...]. Used to compute evidence_hash for dedup and (in future) reverse lookup.';
COMMENT ON COLUMN syntheses.evidence_hash IS 'SHA-256 hex of canonical_json(evidence). Acts as the dedup identity for append-only writes: if the same evidence set appears again, ON CONFLICT DO NOTHING skips the insert. Evidence changes between runs produce a new row (historical accumulation), not an overwrite.';
COMMENT ON COLUMN syntheses.computed_at IS 'When this snapshot was written. Never updated after insert. For the same (subject, kind), ORDER BY computed_at DESC LIMIT 1 gives the latest observation; the full ORDER BY gives the historical timeline.';
COMMENT ON COLUMN syntheses.computed_by IS 'Label identifying the writer process and invocation mode, e.g. "consolidation:weekly:manual" for a manually-triggered consolidation run. Free-text by design — this field is a label for observability, not a dispatch key. Live handlers MUST NOT write rows and MUST NOT use this field.';

-- Dedup indexes — one for each subject identity form. Partial indexes
-- avoid indexing NULL side of the CHECK.
CREATE UNIQUE INDEX uniq_syntheses_by_key ON syntheses
    (subject_type, subject_key, kind, evidence_hash)
    WHERE subject_key IS NOT NULL;

CREATE UNIQUE INDEX uniq_syntheses_by_id ON syntheses
    (subject_type, subject_id, kind, evidence_hash)
    WHERE subject_id IS NOT NULL;

-- Read path index — RecentByKind and retrospective lookups order by
-- computed_at DESC within a (subject_type, kind) window.
CREATE INDEX idx_syntheses_recent_by_kind ON syntheses
    (subject_type, kind, computed_at DESC);

-- Secondary read index — when retrospective lookups filter by specific
-- subject_key (e.g. "show me all snapshots for week 2026-W15").
CREATE INDEX idx_syntheses_by_subject_key ON syntheses
    (subject_type, subject_key, kind, computed_at DESC)
    WHERE subject_key IS NOT NULL;
