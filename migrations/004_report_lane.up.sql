-- Report lane: fan-out research assignments and the agent report corpus.
--
-- Two thin tables:
--
--   research_assignments — a dispatched research task. Fan-out only: HQ/human
--       assigns a topic to an agent. No chaining, no task tree (there is no
--       parent_assignment_id), no acceptance ceremony. Fulfillment is the
--       creation of a report row referencing the assignment — at which point
--       status flips open → fulfilled. An assignment with no report stays
--       'open' and is persisted as store-queryable unfulfilled work; no
--       agent-facing read tool surfaces open assignments yet (reserved for a
--       future read/admin surface).
--
--   reports — an agent-produced research/source artifact, low_trust by default.
--       A report is a FIRST-CLASS corpus member, distinct from notes (human
--       digested knowledge, maturity axis) and contents (editorial/publication,
--       status axis). A report's axis is TRUST (low_trust → trusted); trust is
--       NOT note maturity and a trusted report is a credible SOURCE, never
--       "evergreen digested knowledge". Trust promotion is a human/admin act
--       (not exposed via the agent MCP surface). Low-trust reports are
--       searchable from creation, badged, and downranked — visibility is not
--       gated by trust.

-- ---- research_assignments ------------------------------------------------
-- Created before reports so reports.origin_assignment_id can reference it.
-- research_assignments intentionally has NO foreign key back to reports:
-- the assignment→report link is recovered by querying reports on
-- origin_assignment_id, which avoids a circular FK and keeps the table thin.

CREATE TABLE research_assignments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    topic       TEXT NOT NULL,
    assigned_to TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    assigned_by TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    status      TEXT NOT NULL DEFAULT 'open'
                CHECK (status IN ('open', 'fulfilled')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    fulfilled_at TIMESTAMPTZ,

    CONSTRAINT chk_research_assignment_topic_not_blank
        CHECK (btrim(topic) <> ''),
    -- Pair invariant: fulfilled_at is set exactly when status is 'fulfilled'.
    -- This is a structural floor — the store flips both together in one tx
    -- when a report fulfills the assignment.
    CONSTRAINT chk_research_assignment_fulfilled_pair CHECK (
        (status = 'open'      AND fulfilled_at IS NULL)
        OR
        (status = 'fulfilled' AND fulfilled_at IS NOT NULL)
    )
);

COMMENT ON TABLE research_assignments IS
    'Fan-out research dispatch. HQ/human assigns a topic to an agent; '
    'the agent works autonomously and fulfills it by creating a report row '
    'referencing this assignment. Fan-out only — no parent_assignment_id, no '
    'chaining, no acceptance ceremony. An open assignment with no report is '
    'unfulfilled and store-queryable, but no agent-facing read surface exposes '
    'it yet. Deliberately un-audited: no activity_events trigger fires for this '
    'table (provenance lives on assigned_by + created_at). Distinct from tasks '
    '(the A2A coordination entity, with acknowledge/file_report/revision '
    'lifecycle) — research assignments have no such lifecycle by design.';
COMMENT ON COLUMN research_assignments.topic IS
    'What to research, in free text. Non-blank (chk_research_assignment_topic_not_blank).';
COMMENT ON COLUMN research_assignments.assigned_to IS
    'References agents(name). The agent expected to produce the report. '
    'ON DELETE RESTRICT so a dispatched assignment cannot dangle.';
COMMENT ON COLUMN research_assignments.assigned_by IS
    'References agents(name). The dispatcher (HQ or human). assign_research is '
    'author-gated to hq + human, so this is one of those.';
COMMENT ON COLUMN research_assignments.status IS
    'Lifecycle: open → fulfilled. open = dispatched, no report yet (persisted '
    'and store-queryable; no agent-facing read tool surfaces it yet). '
    'fulfilled = a report referencing this assignment exists. '
    'Set by research.Store, never by trigger. There is no cancel/revision state.';
COMMENT ON COLUMN research_assignments.fulfilled_at IS
    'NULL until a report fulfills this assignment, then set to now() in the same '
    'transaction that creates the report. Paired with status=fulfilled by '
    'chk_research_assignment_fulfilled_pair.';

CREATE INDEX idx_research_assignments_status ON research_assignments(status);
CREATE INDEX idx_research_assignments_assigned_to ON research_assignments(assigned_to);

-- ---- reports -------------------------------------------------------------

CREATE TABLE reports (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title               TEXT NOT NULL,
    body                TEXT NOT NULL DEFAULT '',
    produced_by         TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    origin_assignment_id UUID REFERENCES research_assignments(id) ON DELETE SET NULL,
    trust_status        TEXT NOT NULL DEFAULT 'low_trust'
                        CHECK (trust_status IN ('low_trust', 'trusted')),
    search_vector TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(left(body, 10000), '')), 'C')
    ) STORED,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_report_title_not_blank CHECK (btrim(title) <> '')
);

COMMENT ON TABLE reports IS
    'Agent-produced research/source artifacts — a first-class corpus member, '
    'low_trust by default. Distinct from notes (human-digested private '
    'knowledge, maturity axis) and contents (editorial/publication, status + '
    'is_public axes). A report is a SOURCE, not digested knowledge: a trusted '
    'report is still a source, never an evergreen note. Trust promotion '
    '(low_trust → trusted) is a human/admin act and is NOT exposed on the agent '
    'MCP surface. Reports are searchable from creation (search_knowledge), '
    'badged by source_type=report + trust_status, and downranked relative to '
    'notes/content so agent output never drowns out personal notes. Thin by '
    'design: no topics/tags, no publish lifecycle, no embedding, no maturity, '
    'and deliberately no audit trail (no activity_events trigger fires for this '
    'table; produced_by + created_at carry provenance).';
COMMENT ON COLUMN reports.title IS
    'Short title/summary of the report. Non-blank. Weighted A in search_vector.';
COMMENT ON COLUMN reports.body IS
    'Report body in markdown (the research/source content). Weighted C in '
    'search_vector (first 10000 chars, mirroring contents/notes).';
COMMENT ON COLUMN reports.produced_by IS
    'References agents(name). The agent that produced this report — required '
    'provenance. ON DELETE RESTRICT so a report cannot lose its author.';
COMMENT ON COLUMN reports.origin_assignment_id IS
    'References research_assignments(id). NULL for a standalone report (no '
    'dispatched assignment). Set when the report fulfills a fan-out assignment '
    '— the provenance link. ON DELETE SET NULL: deleting the assignment keeps '
    'the report (the source survives) but drops the provenance pointer.';
COMMENT ON COLUMN reports.trust_status IS
    'Trust axis: low_trust → trusted. Agent reports are born low_trust. '
    'Promotion to trusted is a human/admin verdict (research.Store.SetReportTrust '
    'is schema/store-ready, but no production human UI exists yet — deferred), '
    'never an agent MCP action and never the same thing as note maturity. '
    'low_trust controls search RANKING (downranked + badged), NOT visibility.';
COMMENT ON COLUMN reports.search_vector IS
    'Generated tsvector for full-text search. Mirrors notes.search_vector shape '
    '(title weight A, body weight C). Reports are FTS-only — no embedding column.';

CREATE INDEX idx_reports_produced_by ON reports(produced_by);
CREATE INDEX idx_reports_trust_status ON reports(trust_status);
CREATE INDEX idx_reports_origin_assignment ON reports(origin_assignment_id)
    WHERE origin_assignment_id IS NOT NULL;
CREATE INDEX idx_reports_search ON reports USING GIN(search_vector);
CREATE INDEX idx_reports_created_at ON reports(created_at DESC);
