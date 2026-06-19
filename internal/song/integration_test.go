// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles the testcontainers-backed admin handler tests
// for the song package. Mutations are driven through api.ActorMiddleware via
// httptest — mirroring the production adminMid chain — so the handlers'
// mustAdminTx contract is exercised end-to-end. The song tables carry no
// audit triggers and no created_by FK (single human writer, by design — see
// migrations/001_initial.up.sql).
//
// Coverage (each test names the bug it would catch):
//   - CreateDefaults — POST with only title_ja persists empty study fields and
//     private defaults; a broken default or response/persistence mismatch
//     fails here.
//   - StudyFieldsRoundTrip — lyrics/translation/vocabulary persist verbatim
//     (multi-line allowed) and an explicit Update clears one field; a column
//     mismatch or a wrong COALESCE arg fails here.
//   - BlankTitleRejected — a blank/whitespace title_ja is a 400, never a CHECK
//     500; a missing handler guard fails here.
//   - ReflectionThreadOrderingAndDefaults — entry_date asc with created_at
//     tiebreak, default entry_date = today, multi-line body round-trip.
//     A missing/DESC ORDER BY or a broken default fails here.
//   - ReflectionMembershipMismatch — {id, rid} binding: a mismatch is a 404
//     and never a cross-song write; a WHERE clause missing song_id fails here.
//   - CascadeDelete — deleting a song deletes its diary and 404s the page.
//   - ReflectionUnderMissingSong — FK violation surfaces as 404, not 500.
//   - BlankReflectionBodyRejected — a blank body is a 400, never a CHECK 500.
//
// Run with:
//
//	go test -tags=integration ./internal/song/
package song_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/song"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// truncate clears the song tables so each test starts clean.
// song_reflections goes with songs via CASCADE.
func truncate(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(), `TRUNCATE songs CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func newHandler() *song.Handler {
	return song.NewHandler(song.NewStore(testPool), slog.Default())
}

// serve runs an admin mutation through ActorMiddleware (actor="human") into
// the given handler, mirroring the production adminMid chain.
func serve(t *testing.T, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	mid := api.ActorMiddleware(testPool, "human", slog.Default())
	wrapped := mid(h)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	return rec
}

// jsonReq builds a request with a JSON body and the admin content type.
func jsonReq(t *testing.T, method, target string, body any) *http.Request {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// dbToday returns the database's CURRENT_DATE — the clock the entry_date
// default uses.
func dbToday(t *testing.T) string {
	t.Helper()
	var d string
	if err := testPool.QueryRow(t.Context(),
		`SELECT to_char(CURRENT_DATE, 'YYYY-MM-DD')`).Scan(&d); err != nil {
		t.Fatalf("querying CURRENT_DATE: %v", err)
	}
	return d
}

// reflectionWire mirrors the handler's reflection wire shape.
type reflectionWire struct {
	ID        uuid.UUID `json:"id"`
	SongID    uuid.UUID `json:"song_id"`
	EntryDate string    `json:"entry_date"`
	Body      string    `json:"body"`
}

// songWire mirrors the handler's song wire shape; Reflections is populated on
// the detail (Get) response only.
type songWire struct {
	ID          uuid.UUID        `json:"id"`
	TitleJa     string           `json:"title_ja"`
	Album       string           `json:"album"`
	LyricsJa    string           `json:"lyrics_ja"`
	Translation string           `json:"translation"`
	Vocabulary  string           `json:"vocabulary"`
	IsPublic    bool             `json:"is_public"`
	Reflections []reflectionWire `json:"reflections"`
}

func decodeSong(t *testing.T, body []byte) songWire {
	t.Helper()
	var env struct {
		Data songWire `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode song response: %v (body=%s)", err, body)
	}
	return env.Data
}

func decodeReflection(t *testing.T, body []byte) reflectionWire {
	t.Helper()
	var env struct {
		Data reflectionWire `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode reflection response: %v (body=%s)", err, body)
	}
	return env.Data
}

// createSong POSTs a song through the middleware and returns the 201 wire
// shape.
func createSong(t *testing.T, h *song.Handler, body map[string]any) songWire {
	t.Helper()
	rec := serve(t, h.Create, jsonReq(t, http.MethodPost, "/api/admin/knowledge/songs", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("Create(%v) status = %d, want %d (body=%s)", body, rec.Code, http.StatusCreated, rec.Body.Bytes())
	}
	return decodeSong(t, rec.Body.Bytes())
}

// createReflection POSTs a diary entry under a song and returns the 201 wire
// shape.
func createReflection(t *testing.T, h *song.Handler, songID uuid.UUID, body map[string]any) reflectionWire {
	t.Helper()
	req := jsonReq(t, http.MethodPost, "/api/admin/knowledge/songs/"+songID.String()+"/reflections", body)
	req.SetPathValue("id", songID.String())
	rec := serve(t, h.CreateReflection, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("CreateReflection(%v) status = %d, want %d (body=%s)", body, rec.Code, http.StatusCreated, rec.Body.Bytes())
	}
	return decodeReflection(t, rec.Body.Bytes())
}

// getDetail GETs the song page (song + reflection thread).
func getDetail(t *testing.T, h *song.Handler, id uuid.UUID) (songWire, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/knowledge/songs/"+id.String(), nil)
	req.SetPathValue("id", id.String())
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusOK {
		return songWire{}, rec.Code
	}
	return decodeSong(t, rec.Body.Bytes()), rec.Code
}

// putSong PUTs a partial update and returns the recorder.
func putSong(t *testing.T, h *song.Handler, id uuid.UUID, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	req := jsonReq(t, http.MethodPut, "/api/admin/knowledge/songs/"+id.String(), body)
	req.SetPathValue("id", id.String())
	return serve(t, h.Update, req)
}

func TestIntegration_Song_CreateDefaults(t *testing.T) {
	truncate(t)
	h := newHandler()

	got := createSong(t, h, map[string]any{"title_ja": "だから僕は音楽を辞めた"})

	if got.TitleJa != "だから僕は音楽を辞めた" {
		t.Errorf("Create title_ja = %q, want %q", got.TitleJa, "だから僕は音楽を辞めた")
	}
	if got.Album != "" || got.LyricsJa != "" || got.Translation != "" || got.Vocabulary != "" {
		t.Errorf("Create default study fields = (%q,%q,%q,%q), want all empty",
			got.Album, got.LyricsJa, got.Translation, got.Vocabulary)
	}
	if got.IsPublic {
		t.Error("Create default is_public = true, want false")
	}

	// The response must reflect what was persisted, not just echoed.
	var dbTitle string
	if err := testPool.QueryRow(t.Context(),
		`SELECT title_ja FROM songs WHERE id = $1`, got.ID).Scan(&dbTitle); err != nil {
		t.Fatalf("reading song row back: %v", err)
	}
	if dbTitle != "だから僕は音楽を辞めた" {
		t.Errorf("persisted title_ja = %q, want %q", dbTitle, "だから僕は音楽を辞めた")
	}
}

func TestIntegration_Song_StudyFieldsRoundTrip(t *testing.T) {
	truncate(t)
	h := newHandler()

	// Multi-line lyrics and a translation are owner-filled, stored verbatim.
	lyrics := "夜のうちに\n吹き荒ぶ風"
	got := createSong(t, h, map[string]any{
		"title_ja":    "藍二乗",
		"album":       "だから僕は音楽を辞めた",
		"lyrics_ja":   lyrics,
		"translation": "Within the night\nthe wind rages",
		"vocabulary":  "吹き荒ぶ (ふきすさぶ) — to blow violently",
	})
	if got.LyricsJa != lyrics {
		t.Errorf("lyrics_ja round-trip = %q, want %q", got.LyricsJa, lyrics)
	}
	if got.Album != "だから僕は音楽を辞めた" {
		t.Errorf("album round-trip = %q, want %q", got.Album, "だから僕は音楽を辞めた")
	}

	// An explicit empty string through Update clears the vocabulary field; an
	// omitted field stays unchanged.
	rec := putSong(t, h, got.ID, map[string]any{"vocabulary": ""})
	if rec.Code != http.StatusOK {
		t.Fatalf("Update(clear vocabulary) status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.Bytes())
	}
	updated := decodeSong(t, rec.Body.Bytes())
	if updated.Vocabulary != "" {
		t.Errorf("vocabulary after clear = %q, want empty", updated.Vocabulary)
	}
	if updated.LyricsJa != lyrics {
		t.Errorf("lyrics_ja after unrelated update = %q, want preserved %q", updated.LyricsJa, lyrics)
	}
}

func TestIntegration_Song_BlankTitleRejected(t *testing.T) {
	truncate(t)
	h := newHandler()

	// A whitespace-only title_ja must be a 400, never a CHECK-violation 500.
	rec := serve(t, h.Create, jsonReq(t, http.MethodPost, "/api/admin/knowledge/songs",
		map[string]any{"title_ja": "   "}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Create(blank title_ja) status = %d, want %d (handler guards the CHECK)",
			rec.Code, http.StatusBadRequest)
	}
}

func TestIntegration_Song_ReflectionThreadOrderingAndDefaults(t *testing.T) {
	truncate(t)
	h := newHandler()
	today := dbToday(t)

	sg := createSong(t, h, map[string]any{"title_ja": "Threaded Song"})

	// Created out of diary order on purpose; the two 06-01 entries exercise
	// the created_at tiebreak (insertion order).
	createReflection(t, h, sg.ID, map[string]any{"body": "second day", "entry_date": "2026-06-02"})
	createReflection(t, h, sg.ID, map[string]any{"body": "first day", "entry_date": "2026-06-01"})
	createReflection(t, h, sg.ID, map[string]any{"body": "first day, later thought", "entry_date": "2026-06-01"})
	multiline := createReflection(t, h, sg.ID, map[string]any{"body": "line one\nline two"})

	// Default entry_date is today (the DB clock).
	if multiline.EntryDate != today {
		t.Errorf("default entry_date = %q, want %q", multiline.EntryDate, today)
	}

	detail, code := getDetail(t, h, sg.ID)
	if code != http.StatusOK {
		t.Fatalf("Get() status = %d, want %d", code, http.StatusOK)
	}
	gotBodies := make([]string, len(detail.Reflections))
	for i, ref := range detail.Reflections {
		gotBodies[i] = ref.Body
	}
	// entry_date asc, created_at asc tiebreak; the dateless entry lands last
	// because today follows the seeded 2026-06 dates.
	wantBodies := []string{"first day", "first day, later thought", "second day", "line one\nline two"}
	if diff := cmp.Diff(wantBodies, gotBodies); diff != "" {
		t.Errorf("reflection thread order mismatch (-want +got):\n%s", diff)
	}
}

func TestIntegration_Song_ReflectionMembershipMismatch(t *testing.T) {
	truncate(t)
	h := newHandler()

	songA := createSong(t, h, map[string]any{"title_ja": "Song A"})
	songB := createSong(t, h, map[string]any{"title_ja": "Song B"})
	ref := createReflection(t, h, songA.ID, map[string]any{"body": "belongs to A"})

	// Update through the wrong song must 404 and write nothing.
	target := "/api/admin/knowledge/songs/" + songB.ID.String() + "/reflections/" + ref.ID.String()
	req := jsonReq(t, http.MethodPut, target, map[string]any{"body": "hijacked"})
	req.SetPathValue("id", songB.ID.String())
	req.SetPathValue("rid", ref.ID.String())
	if rec := serve(t, h.UpdateReflection, req); rec.Code != http.StatusNotFound {
		t.Fatalf("UpdateReflection(wrong song) status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	var body string
	if err := testPool.QueryRow(t.Context(),
		`SELECT body FROM song_reflections WHERE id = $1`, ref.ID).Scan(&body); err != nil {
		t.Fatalf("reading reflection back: %v", err)
	}
	if body != "belongs to A" {
		t.Errorf("reflection body after mismatched update = %q, want untouched %q", body, "belongs to A")
	}

	// Delete through the wrong song must 404 and remove nothing.
	req = httptest.NewRequest(http.MethodDelete, target, nil)
	req.SetPathValue("id", songB.ID.String())
	req.SetPathValue("rid", ref.ID.String())
	if rec := serve(t, h.DeleteReflection, req); rec.Code != http.StatusNotFound {
		t.Fatalf("DeleteReflection(wrong song) status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM song_reflections WHERE id = $1`, ref.ID).Scan(&n); err != nil {
		t.Fatalf("counting reflection: %v", err)
	}
	if n != 1 {
		t.Fatalf("reflection count after mismatched delete = %d, want 1", n)
	}

	// The correctly-bound delete succeeds.
	target = "/api/admin/knowledge/songs/" + songA.ID.String() + "/reflections/" + ref.ID.String()
	req = httptest.NewRequest(http.MethodDelete, target, nil)
	req.SetPathValue("id", songA.ID.String())
	req.SetPathValue("rid", ref.ID.String())
	if rec := serve(t, h.DeleteReflection, req); rec.Code != http.StatusNoContent {
		t.Errorf("DeleteReflection(right song) status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestIntegration_Song_CascadeDelete(t *testing.T) {
	truncate(t)
	h := newHandler()

	sg := createSong(t, h, map[string]any{"title_ja": "Doomed Song"})
	createReflection(t, h, sg.ID, map[string]any{"body": "entry one"})
	createReflection(t, h, sg.ID, map[string]any{"body": "entry two"})

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/knowledge/songs/"+sg.ID.String(), nil)
	req.SetPathValue("id", sg.ID.String())
	if rec := serve(t, h.Delete, req); rec.Code != http.StatusNoContent {
		t.Fatalf("Delete() status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM song_reflections WHERE song_id = $1`, sg.ID).Scan(&n); err != nil {
		t.Fatalf("counting reflections: %v", err)
	}
	if n != 0 {
		t.Errorf("reflections after song delete = %d, want 0 (cascade)", n)
	}

	if _, code := getDetail(t, h, sg.ID); code != http.StatusNotFound {
		t.Errorf("Get(deleted) status = %d, want %d", code, http.StatusNotFound)
	}
}

func TestIntegration_Song_ReflectionUnderMissingSong(t *testing.T) {
	truncate(t)
	h := newHandler()

	ghost := uuid.New()
	req := jsonReq(t, http.MethodPost, "/api/admin/knowledge/songs/"+ghost.String()+"/reflections",
		map[string]any{"body": "orphan"})
	req.SetPathValue("id", ghost.String())
	if rec := serve(t, h.CreateReflection, req); rec.Code != http.StatusNotFound {
		t.Errorf("CreateReflection(missing song) status = %d, want %d (FK must map to 404, not 500)",
			rec.Code, http.StatusNotFound)
	}
}

func TestIntegration_Song_BlankReflectionBodyRejected(t *testing.T) {
	truncate(t)
	h := newHandler()

	sg := createSong(t, h, map[string]any{"title_ja": "Guarded Song"})

	// A whitespace-only body must be a 400, never a CHECK-violation 500.
	req := jsonReq(t, http.MethodPost, "/api/admin/knowledge/songs/"+sg.ID.String()+"/reflections",
		map[string]any{"body": "   "})
	req.SetPathValue("id", sg.ID.String())
	if rec := serve(t, h.CreateReflection, req); rec.Code != http.StatusBadRequest {
		t.Errorf("CreateReflection(blank body) status = %d, want %d (handler guards the CHECK)",
			rec.Code, http.StatusBadRequest)
	}
}
