-- ============================================================
-- Readings — literature shelf + reading diary
--
-- A reading is one book on Koopa's personal shelf; a reading_reflection is
-- one dated diary entry under a book. Deeply private by design: this domain
-- has ZERO agent surface — no MCP tool reads or writes these tables, they
-- are not indexed by search_knowledge (no embedding column, no tsvector),
-- and the only write path is the admin HTTP API behind adminMid.
--
-- No audit triggers on either table — deliberate, not an omission. Every
-- write comes from the single human admin behind adminMid, so an actor
-- audit trail would record a constant; and diary entries deliberately stay
-- out of the cross-cutting activity_events feed (the reading diary is not
-- activity to be surfaced — it is private writing).
--
-- There is deliberately NO rating column, ever — reflections are the only
-- form of evaluation (owner decision).
-- ============================================================

CREATE TABLE readings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title       TEXT NOT NULL,
    author      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'want_to_read'
        CHECK (status IN ('want_to_read', 'reading', 'finished', 'abandoned')),
    started_on  DATE,
    finished_on DATE,
    is_public   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_reading_title_not_blank
        CHECK (btrim(title) <> '')
);

COMMENT ON TABLE readings IS
    'Literature reading shelf — one row per book, Koopa-private. Evaluation '
    'happens only through reading_reflections (dated diary entries); there is '
    'intentionally no rating column. No agent surface: not exposed via MCP, '
    'not in the search_knowledge corpus, admin HTTP only.';
COMMENT ON COLUMN readings.title IS
    'Book title as Koopa records it. Required, never blank (chk_reading_title_not_blank).';
COMMENT ON COLUMN readings.author IS
    'Author name(s), free text. Empty string when not recorded — "unknown author" '
    'carries no distinct meaning from "not entered", so NOT NULL DEFAULT '''' '
    'instead of nullable.';
COMMENT ON COLUMN readings.status IS
    'Shelf state: want_to_read → reading → finished | abandoned. The CHECK '
    'closes the value set; transitions are NOT schema-enforced — any change is '
    'allowed (abandoned books get picked back up, finished books get re-read). '
    'Set by the admin HTTP handler, never by trigger.';
COMMENT ON COLUMN readings.started_on IS
    'Date Koopa started reading. NULL while the book sits on the want-to-read '
    'shelf or when the start date was never recorded.';
COMMENT ON COLUMN readings.finished_on IS
    'Date Koopa finished (or gave up on) the book. NULL until the reading '
    'concludes. The handler auto-stamps today on a transition to finished when '
    'no explicit date is supplied.';
COMMENT ON COLUMN readings.is_public IS
    'Reserved for a future public shelf. Default false; nothing public-facing '
    'reads this yet — flipping it has no effect until a public surface exists.';
COMMENT ON COLUMN readings.created_at IS
    'Row creation time. Set by the database, never updated.';
COMMENT ON COLUMN readings.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

-- status is the only WHERE-clause column on readings (list filter).
CREATE INDEX idx_readings_status ON readings(status);

CREATE TABLE reading_reflections (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reading_id UUID NOT NULL REFERENCES readings(id) ON DELETE CASCADE,
    entry_date DATE NOT NULL DEFAULT CURRENT_DATE,
    body       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_reading_reflection_body_not_blank
        CHECK (btrim(body) <> '')
);

COMMENT ON TABLE reading_reflections IS
    'Reading diary — dated entries under one book, shown as a time-ordered '
    'thread (entry_date, then created_at) on the book page. Many per book. '
    'Private like readings: no agent surface, no search corpus, admin HTTP only.';
COMMENT ON COLUMN reading_reflections.reading_id IS
    'The book this entry belongs to. ON DELETE CASCADE — deleting a book '
    'deletes its entire diary; the entries have no meaning without the book.';
COMMENT ON COLUMN reading_reflections.entry_date IS
    'The diary date the entry belongs to — the day of reading, not necessarily '
    'the day it was typed in. Defaults to the current date; the handler applies '
    'the same default when the field is omitted.';
COMMENT ON COLUMN reading_reflections.body IS
    'The diary entry text. Required, never blank '
    '(chk_reading_reflection_body_not_blank). Free-form prose; newlines allowed.';
COMMENT ON COLUMN reading_reflections.created_at IS
    'Row creation time. Tiebreak for thread ordering when two entries share an '
    'entry_date.';
COMMENT ON COLUMN reading_reflections.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

-- The thread query filters by reading_id and orders by (entry_date, created_at).
CREATE INDEX idx_reading_reflections_thread
    ON reading_reflections(reading_id, entry_date, created_at);
