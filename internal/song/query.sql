-- Queries for the song package — the songs + song_reflections tables (the
-- ヨルシカ shelf). title_ja carries a
-- not-blank CHECK; the Go layer validates before writing so the constraint
-- never surfaces as a 500. The study fields (lyrics_ja, translation,
-- vocabulary) are owner-filled free text, never generated. No audit triggers
-- fire on these tables — single human writer, the diary stays out of activity
-- feeds (same privacy posture as the reading shelf).

-- name: CreateSong :one
INSERT INTO songs (
    title_ja, album, lyrics_ja, translation, vocabulary
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING id, title_ja, album, lyrics_ja, translation, vocabulary, is_public,
          created_at, updated_at;

-- name: SongByID :one
SELECT id, title_ja, album, lyrics_ja, translation, vocabulary, is_public,
       created_at, updated_at
FROM songs
WHERE id = $1;

-- name: Songs :many
-- Shelf list, ordered by recency of edit. The whole table is ヨルシカ, so
-- there is no artist filter; grouping by album is the frontend's concern.
SELECT id, title_ja, album, lyrics_ja, translation, vocabulary, is_public,
       created_at, updated_at
FROM songs
ORDER BY updated_at DESC;

-- name: UpdateSong :one
-- Partial update — omitted (NULL) args leave the column unchanged. The study
-- fields are plain text columns, so an explicit empty string clears one while
-- a NULL leaves it; the Go layer passes a pointer only when the caller sent
-- the field.
UPDATE songs SET
    title_ja = COALESCE(sqlc.narg('title_ja'), title_ja),
    album = COALESCE(sqlc.narg('album'), album),
    lyrics_ja = COALESCE(sqlc.narg('lyrics_ja'), lyrics_ja),
    translation = COALESCE(sqlc.narg('translation'), translation),
    vocabulary = COALESCE(sqlc.narg('vocabulary'), vocabulary),
    is_public = COALESCE(sqlc.narg('is_public')::boolean, is_public),
    updated_at = now()
WHERE id = @id
RETURNING id, title_ja, album, lyrics_ja, translation, vocabulary, is_public,
          created_at, updated_at;

-- name: DeleteSong :execrows
-- ON DELETE CASCADE removes the song's entire reflection thread with it.
DELETE FROM songs WHERE id = $1;

-- name: CreateSongReflection :one
-- A NULL entry_date defaults to today. COALESCE here rather than relying on
-- the column DEFAULT so the "today" clock is the same (the database's
-- CURRENT_DATE) whether the handler passes a date or not.
INSERT INTO song_reflections (
    song_id, entry_date, body
) VALUES (
    $1, COALESCE(sqlc.narg('entry_date')::date, CURRENT_DATE), $2
)
RETURNING id, song_id, entry_date, body, created_at, updated_at;

-- name: ReflectionsForSong :many
-- The diary thread for one song: diary-date order, creation order as the
-- same-day tiebreak. Served by idx_song_reflections_thread.
SELECT id, song_id, entry_date, body, created_at, updated_at
FROM song_reflections
WHERE song_id = $1
ORDER BY entry_date ASC, created_at ASC;

-- name: UpdateSongReflection :one
-- Partial update of a diary entry, bound to its parent song: the WHERE clause
-- enforces membership, so a {song_id, id} mismatch is a no-row miss (404)
-- rather than a cross-song write.
UPDATE song_reflections SET
    body = COALESCE(sqlc.narg('body'), body),
    entry_date = COALESCE(sqlc.narg('entry_date')::date, entry_date),
    updated_at = now()
WHERE id = @id AND song_id = @song_id
RETURNING id, song_id, entry_date, body, created_at, updated_at;

-- name: DeleteSongReflection :execrows
-- Delete a diary entry, bound to its parent song (same membership guard as
-- UpdateSongReflection).
DELETE FROM song_reflections WHERE id = @id AND song_id = @song_id;

-- ============================================================
-- search_knowledge corpus (source_type=song)
--
-- The ヨルシカ shelf and its reflection diary feed the read-only
-- search_knowledge corpus — the shelf's first agent-visible surface. Both a
-- song-row hit and a reflection hit surface as source_type=song, linking back
-- to the parent song (its id + title_ja). A song hit's excerpt is the title;
-- a reflection hit's excerpt is the diary body. Mirrors the reading corpus
-- queries exactly.
-- ============================================================

-- name: SongsMissingEmbedding :many
-- Shelf rows the embedding reconciler still has to process. Oldest first.
-- Embed input = title_ja + album + the study fields (lyrics/translation/vocabulary).
SELECT id, title_ja, album, lyrics_ja, translation, vocabulary
FROM songs
WHERE embedding IS NULL
ORDER BY created_at
LIMIT $1;

-- name: SetSongEmbedding :exec
-- Persist a derived embedding. updated_at is deliberately untouched.
UPDATE songs SET embedding = $2 WHERE id = $1;

-- name: SongReflectionsMissingEmbedding :many
-- Diary rows the reconciler still has to process. Embed input = body.
SELECT id, body
FROM song_reflections
WHERE embedding IS NULL
ORDER BY created_at
LIMIT $1;

-- name: SetSongReflectionEmbedding :exec
UPDATE song_reflections SET embedding = $2 WHERE id = $1;

-- name: SearchSongCorpus :many
-- FTS over the song corpus: shelf rows + reflection entries, both folded under
-- the parent song. excerpt carries the matched text (song title for a shelf
-- hit, diary body for a reflection hit). Ordered by ts_rank across the union.
SELECT song_id, title, excerpt, created_at
FROM (
    SELECT s.id AS song_id,
           s.title_ja AS title,
           s.title_ja AS excerpt,
           s.created_at AS created_at,
           ts_rank(s.search_vector, websearch_to_tsquery('simple', $1)) AS rank
    FROM songs s
    WHERE s.search_vector @@ websearch_to_tsquery('simple', $1)
    UNION ALL
    SELECT sr.song_id AS song_id,
           s.title_ja AS title,
           sr.body AS excerpt,
           sr.created_at AS created_at,
           ts_rank(sr.search_vector, websearch_to_tsquery('simple', $1)) AS rank
    FROM song_reflections sr
    JOIN songs s ON s.id = sr.song_id
    WHERE sr.search_vector @@ websearch_to_tsquery('simple', $1)
) hits
ORDER BY rank DESC
LIMIT $2;

-- name: SemanticSearchSongCorpus :many
-- pgvector cosine search over the song corpus: shelf rows + reflection entries,
-- both folded under the parent song. Mirrors SearchSongCorpus's projection;
-- rows without an embedding are skipped. Ordered by cosine distance.
SELECT song_id, title, excerpt, created_at
FROM (
    SELECT s.id AS song_id,
           s.title_ja AS title,
           s.title_ja AS excerpt,
           s.created_at AS created_at,
           (s.embedding <=> @target_embedding::vector) AS distance
    FROM songs s
    WHERE s.embedding IS NOT NULL
    UNION ALL
    SELECT sr.song_id AS song_id,
           s.title_ja AS title,
           sr.body AS excerpt,
           sr.created_at AS created_at,
           (sr.embedding <=> @target_embedding::vector) AS distance
    FROM song_reflections sr
    JOIN songs s ON s.id = sr.song_id
    WHERE sr.embedding IS NOT NULL
) hits
ORDER BY distance
LIMIT @max_results;
