// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles the testcontainers-backed admin handler tests
// for the reading package. Mutations are driven through api.ActorMiddleware
// via httptest — mirroring the production adminMid chain — so the handlers'
// mustAdminTx contract is exercised end-to-end. Unlike the goal suite, no
// agent registry sync runs in TestMain: the reading tables carry no audit
// triggers and no created_by FK (single human writer, by design — see
// migrations/004_readings.up.sql).
//
// Coverage (each test names the bug it would catch):
//   - CreateDefaults — POST without status persists want_to_read; a broken
//     default or response/persistence mismatch fails here.
//   - ListStatusFilter — ?status= narrowing and 400 on an unknown value;
//     a mishandled NULL filter arg that returns everything fails here.
//   - FinishedAutoStamp — the Update convenience rule: transition to
//     finished stamps today, an explicit date wins, an already-recorded
//     date is never overwritten, abandoned does not stamp. A wrong
//     COALESCE order in UpdateReading fails here.
//   - ReflectionThreadOrderingAndDefaults — entry_date asc with created_at
//     tiebreak, default entry_date = today, multi-line body round-trip.
//     A missing/DESC ORDER BY or a broken default fails here.
//   - ReflectionMembershipMismatch — {id, rid} binding: a mismatch is a
//     404 and never a cross-book write; a WHERE clause missing reading_id
//     fails here.
//   - CascadeDelete — deleting a book deletes its diary and 404s the page.
//   - ReflectionUnderMissingReading — FK violation surfaces as 404, not 500.
//
// Run with:
//
//	go test -tags=integration ./internal/reading/
package reading_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/reading"
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

// truncate clears the reading tables so each test starts clean.
// reading_reflections goes with readings via CASCADE.
func truncate(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(), `TRUNCATE readings CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func newHandler() *reading.Handler {
	return reading.NewHandler(reading.NewStore(testPool), slog.Default())
}

// serve runs an admin mutation through ActorMiddleware (actor="human")
// into the given handler, mirroring the production adminMid chain.
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

// dbToday returns the database's CURRENT_DATE — the clock both the
// finished auto-stamp and the entry_date default use.
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
	ReadingID uuid.UUID `json:"reading_id"`
	EntryDate string    `json:"entry_date"`
	Body      string    `json:"body"`
}

// readingWire mirrors the handler's reading wire shape; Reflections is
// populated on the detail (Get) response only.
type readingWire struct {
	ID          uuid.UUID        `json:"id"`
	Title       string           `json:"title"`
	Author      string           `json:"author"`
	Status      string           `json:"status"`
	StartedOn   *string          `json:"started_on"`
	FinishedOn  *string          `json:"finished_on"`
	IsPublic    bool             `json:"is_public"`
	Reflections []reflectionWire `json:"reflections"`
}

func decodeReading(t *testing.T, body []byte) readingWire {
	t.Helper()
	var env struct {
		Data readingWire `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode reading response: %v (body=%s)", err, body)
	}
	return env.Data
}

func decodeReadings(t *testing.T, body []byte) []readingWire {
	t.Helper()
	var env struct {
		Data []readingWire `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode readings response: %v (body=%s)", err, body)
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

// createReading POSTs a reading through the middleware and returns the 201
// wire shape.
func createReading(t *testing.T, h *reading.Handler, body map[string]any) readingWire {
	t.Helper()
	rec := serve(t, h.Create, jsonReq(t, http.MethodPost, "/api/admin/knowledge/readings", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("Create(%v) status = %d, want %d (body=%s)", body, rec.Code, http.StatusCreated, rec.Body.Bytes())
	}
	return decodeReading(t, rec.Body.Bytes())
}

// createReflection POSTs a diary entry under a reading and returns the 201
// wire shape.
func createReflection(t *testing.T, h *reading.Handler, readingID uuid.UUID, body map[string]any) reflectionWire {
	t.Helper()
	req := jsonReq(t, http.MethodPost, "/api/admin/knowledge/readings/"+readingID.String()+"/reflections", body)
	req.SetPathValue("id", readingID.String())
	rec := serve(t, h.CreateReflection, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("CreateReflection(%v) status = %d, want %d (body=%s)", body, rec.Code, http.StatusCreated, rec.Body.Bytes())
	}
	return decodeReflection(t, rec.Body.Bytes())
}

// getDetail GETs the book page (reading + reflection thread).
func getDetail(t *testing.T, h *reading.Handler, id uuid.UUID) (readingWire, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/knowledge/readings/"+id.String(), nil)
	req.SetPathValue("id", id.String())
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusOK {
		return readingWire{}, rec.Code
	}
	return decodeReading(t, rec.Body.Bytes()), rec.Code
}

// putReading PUTs a partial update and returns the recorder.
func putReading(t *testing.T, h *reading.Handler, id uuid.UUID, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	req := jsonReq(t, http.MethodPut, "/api/admin/knowledge/readings/"+id.String(), body)
	req.SetPathValue("id", id.String())
	return serve(t, h.Update, req)
}

func TestIntegration_Reading_CreateDefaults(t *testing.T) {
	truncate(t)
	h := newHandler()

	got := createReading(t, h, map[string]any{"title": "Stories of Your Life and Others"})

	if got.Status != "want_to_read" {
		t.Errorf("Create default status = %q, want %q", got.Status, "want_to_read")
	}
	if got.Author != "" {
		t.Errorf("Create default author = %q, want empty", got.Author)
	}
	if got.StartedOn != nil || got.FinishedOn != nil {
		t.Errorf("Create default dates = (%v, %v), want (nil, nil)", got.StartedOn, got.FinishedOn)
	}
	if got.IsPublic {
		t.Error("Create default is_public = true, want false")
	}

	// The response must reflect what was persisted, not just echoed.
	var dbStatus string
	if err := testPool.QueryRow(t.Context(),
		`SELECT status FROM readings WHERE id = $1`, got.ID).Scan(&dbStatus); err != nil {
		t.Fatalf("reading row back: %v", err)
	}
	if dbStatus != "want_to_read" {
		t.Errorf("persisted status = %q, want %q", dbStatus, "want_to_read")
	}
}

func TestIntegration_Reading_ListStatusFilter(t *testing.T) {
	truncate(t)
	h := newHandler()

	createReading(t, h, map[string]any{"title": "Wishlist Book"})
	current := createReading(t, h, map[string]any{"title": "Current Book", "status": "reading"})
	createReading(t, h, map[string]any{"title": "Done Book", "status": "finished"})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/knowledge/readings?status=reading", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("List(status=reading) status = %d, want %d", rec.Code, http.StatusOK)
	}
	rows := decodeReadings(t, rec.Body.Bytes())
	if len(rows) != 1 || rows[0].ID != current.ID {
		t.Errorf("List(status=reading) = %d rows (first id %v), want exactly the reading-status book %v",
			len(rows), idOrNone(rows), current.ID)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/admin/knowledge/readings", nil)
	rec = httptest.NewRecorder()
	h.List(rec, req)
	if got := len(decodeReadings(t, rec.Body.Bytes())); got != 3 {
		t.Errorf("List() = %d rows, want 3", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/admin/knowledge/readings?status=bogus", nil)
	rec = httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("List(status=bogus) status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// idOrNone is a failure-message helper for empty result slices.
func idOrNone(rows []readingWire) any {
	if len(rows) == 0 {
		return "none"
	}
	return rows[0].ID
}

func TestIntegration_Reading_FinishedAutoStamp(t *testing.T) {
	truncate(t)
	h := newHandler()
	today := dbToday(t)

	// Transition to finished with no finished_on → stamped today.
	auto := createReading(t, h, map[string]any{"title": "Auto Stamp", "status": "reading"})
	rec := putReading(t, h, auto.ID, map[string]any{"status": "finished"})
	if rec.Code != http.StatusOK {
		t.Fatalf("Update(status=finished) status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.Bytes())
	}
	got := decodeReading(t, rec.Body.Bytes())
	if got.FinishedOn == nil || *got.FinishedOn != today {
		t.Errorf("auto-stamped finished_on = %v, want %q", got.FinishedOn, today)
	}

	// Explicit finished_on wins over the stamp.
	explicit := createReading(t, h, map[string]any{"title": "Explicit Date", "status": "reading"})
	rec = putReading(t, h, explicit.ID, map[string]any{"status": "finished", "finished_on": "2026-01-10"})
	got = decodeReading(t, rec.Body.Bytes())
	if got.FinishedOn == nil || *got.FinishedOn != "2026-01-10" {
		t.Errorf("explicit finished_on = %v, want %q", got.FinishedOn, "2026-01-10")
	}

	// A repeat finished update must NOT move the recorded date to today.
	rec = putReading(t, h, explicit.ID, map[string]any{"status": "finished"})
	got = decodeReading(t, rec.Body.Bytes())
	if got.FinishedOn == nil || *got.FinishedOn != "2026-01-10" {
		t.Errorf("finished_on after repeat finished update = %v, want preserved %q", got.FinishedOn, "2026-01-10")
	}

	// Abandoned is a conclusion without a finish date — no stamp.
	dropped := createReading(t, h, map[string]any{"title": "Dropped", "status": "reading"})
	rec = putReading(t, h, dropped.ID, map[string]any{"status": "abandoned"})
	got = decodeReading(t, rec.Body.Bytes())
	if got.FinishedOn != nil {
		t.Errorf("finished_on after abandoned = %v, want nil", got.FinishedOn)
	}
}

func TestIntegration_Reflection_ThreadOrderingAndDefaults(t *testing.T) {
	truncate(t)
	h := newHandler()
	today := dbToday(t)

	book := createReading(t, h, map[string]any{"title": "Threaded Book", "status": "reading"})

	// Created out of diary order on purpose; the two 06-01 entries
	// exercise the created_at tiebreak (insertion order).
	createReflection(t, h, book.ID, map[string]any{"body": "second day", "entry_date": "2026-06-02"})
	createReflection(t, h, book.ID, map[string]any{"body": "first day", "entry_date": "2026-06-01"})
	createReflection(t, h, book.ID, map[string]any{"body": "first day, later thought", "entry_date": "2026-06-01"})
	multiline := createReflection(t, h, book.ID, map[string]any{"body": "line one\nline two"})

	// Default entry_date is today (the DB clock).
	if multiline.EntryDate != today {
		t.Errorf("default entry_date = %q, want %q", multiline.EntryDate, today)
	}

	detail, code := getDetail(t, h, book.ID)
	if code != http.StatusOK {
		t.Fatalf("Get() status = %d, want %d", code, http.StatusOK)
	}
	gotBodies := make([]string, len(detail.Reflections))
	for i, ref := range detail.Reflections {
		gotBodies[i] = ref.Body
	}
	// entry_date asc, created_at asc tiebreak; the dateless entry lands
	// last because today follows the seeded 2026-06 dates.
	wantBodies := []string{"first day", "first day, later thought", "second day", "line one\nline two"}
	if diff := cmp.Diff(wantBodies, gotBodies); diff != "" {
		t.Errorf("reflection thread order mismatch (-want +got):\n%s", diff)
	}
}

func TestIntegration_Reflection_MembershipMismatch(t *testing.T) {
	truncate(t)
	h := newHandler()

	bookA := createReading(t, h, map[string]any{"title": "Book A"})
	bookB := createReading(t, h, map[string]any{"title": "Book B"})
	ref := createReflection(t, h, bookA.ID, map[string]any{"body": "belongs to A"})

	// Update through the wrong book must 404 and write nothing.
	target := "/api/admin/knowledge/readings/" + bookB.ID.String() + "/reflections/" + ref.ID.String()
	req := jsonReq(t, http.MethodPut, target, map[string]any{"body": "hijacked"})
	req.SetPathValue("id", bookB.ID.String())
	req.SetPathValue("rid", ref.ID.String())
	if rec := serve(t, h.UpdateReflection, req); rec.Code != http.StatusNotFound {
		t.Fatalf("UpdateReflection(wrong book) status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	var body string
	if err := testPool.QueryRow(t.Context(),
		`SELECT body FROM reading_reflections WHERE id = $1`, ref.ID).Scan(&body); err != nil {
		t.Fatalf("reading reflection back: %v", err)
	}
	if body != "belongs to A" {
		t.Errorf("reflection body after mismatched update = %q, want untouched %q", body, "belongs to A")
	}

	// Delete through the wrong book must 404 and remove nothing.
	req = httptest.NewRequest(http.MethodDelete, target, nil)
	req.SetPathValue("id", bookB.ID.String())
	req.SetPathValue("rid", ref.ID.String())
	if rec := serve(t, h.DeleteReflection, req); rec.Code != http.StatusNotFound {
		t.Fatalf("DeleteReflection(wrong book) status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM reading_reflections WHERE id = $1`, ref.ID).Scan(&n); err != nil {
		t.Fatalf("counting reflection: %v", err)
	}
	if n != 1 {
		t.Fatalf("reflection count after mismatched delete = %d, want 1", n)
	}

	// The correctly-bound delete succeeds.
	target = "/api/admin/knowledge/readings/" + bookA.ID.String() + "/reflections/" + ref.ID.String()
	req = httptest.NewRequest(http.MethodDelete, target, nil)
	req.SetPathValue("id", bookA.ID.String())
	req.SetPathValue("rid", ref.ID.String())
	if rec := serve(t, h.DeleteReflection, req); rec.Code != http.StatusNoContent {
		t.Errorf("DeleteReflection(right book) status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestIntegration_Reading_CascadeDelete(t *testing.T) {
	truncate(t)
	h := newHandler()

	book := createReading(t, h, map[string]any{"title": "Doomed Book"})
	createReflection(t, h, book.ID, map[string]any{"body": "entry one"})
	createReflection(t, h, book.ID, map[string]any{"body": "entry two"})

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/knowledge/readings/"+book.ID.String(), nil)
	req.SetPathValue("id", book.ID.String())
	if rec := serve(t, h.Delete, req); rec.Code != http.StatusNoContent {
		t.Fatalf("Delete() status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM reading_reflections WHERE reading_id = $1`, book.ID).Scan(&n); err != nil {
		t.Fatalf("counting reflections: %v", err)
	}
	if n != 0 {
		t.Errorf("reflections after book delete = %d, want 0 (cascade)", n)
	}

	if _, code := getDetail(t, h, book.ID); code != http.StatusNotFound {
		t.Errorf("Get(deleted) status = %d, want %d", code, http.StatusNotFound)
	}
}

func TestIntegration_Reflection_UnderMissingReading(t *testing.T) {
	truncate(t)
	h := newHandler()

	ghost := uuid.New()
	req := jsonReq(t, http.MethodPost, "/api/admin/knowledge/readings/"+ghost.String()+"/reflections",
		map[string]any{"body": "orphan"})
	req.SetPathValue("id", ghost.String())
	if rec := serve(t, h.CreateReflection, req); rec.Code != http.StatusNotFound {
		t.Errorf("CreateReflection(missing reading) status = %d, want %d (FK must map to 404, not 500)",
			rec.Code, http.StatusNotFound)
	}
}

// --- search corpus + embedding source (search_knowledge wiring) ---

// TestIntegration_SearchCorpus_FoldsReflectionUnderBook proves the read-side
// search surface the MCP search_knowledge handler folds in: a shelf row and a
// diary entry both surface as CorpusHit linked to the parent book, with the
// matched text as the excerpt. FTS only (no embedder needed). A broken UNION
// projection or a missing JOIN to the parent title fails here.
func TestIntegration_SearchCorpus_FoldsReflectionUnderBook(t *testing.T) {
	truncate(t)
	store := reading.NewStore(testPool)
	ctx := t.Context()

	book, err := store.Create(ctx, &reading.CreateParams{Title: "Kafka on the Shore", Author: "Murakami"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	const reflTerm = "zqxcorpus"
	if _, err := store.CreateReflection(ctx, book.ID, nil, "the "+reflTerm+" motif recurs"); err != nil {
		t.Fatalf("CreateReflection: %v", err)
	}

	t.Run("reflection body matches, folded under book", func(t *testing.T) {
		hits, err := store.SearchCorpus(ctx, reflTerm, 20)
		if err != nil {
			t.Fatalf("SearchCorpus(%q): %v", reflTerm, err)
		}
		if len(hits) != 1 {
			t.Fatalf("SearchCorpus(%q) = %d hits, want 1", reflTerm, len(hits))
		}
		if hits[0].ReadingID != book.ID {
			t.Errorf("hit.ReadingID = %s, want parent book %s", hits[0].ReadingID, book.ID)
		}
		if hits[0].Title != "Kafka on the Shore" {
			t.Errorf("hit.Title = %q, want parent book title", hits[0].Title)
		}
		if !strings.Contains(hits[0].Excerpt, reflTerm) {
			t.Errorf("hit.Excerpt = %q, want the diary body containing %q", hits[0].Excerpt, reflTerm)
		}
	})

	t.Run("author matches the shelf row", func(t *testing.T) {
		hits, err := store.SearchCorpus(ctx, "Murakami", 20)
		if err != nil {
			t.Fatalf("SearchCorpus(Murakami): %v", err)
		}
		var found bool
		for _, h := range hits {
			if h.ReadingID == book.ID && h.Excerpt == "Kafka on the Shore" {
				found = true
			}
		}
		if !found {
			t.Errorf("author search did not surface the shelf row (excerpt=title); got %+v", hits)
		}
	})
}

// TestIntegration_EmbeddingSources_ListMissing proves the reconciler-facing
// SQL: freshly seeded rows have NULL embeddings and are returned by the shelf
// and reflection sources' MissingEmbeddings, with the document text the embed
// derives from (title+author for the shelf, body for the diary). This is the
// DB half of the embedding write path — the Gemini call needs GEMINI_API_KEY,
// so only the query is exercised here.
func TestIntegration_EmbeddingSources_ListMissing(t *testing.T) {
	truncate(t)
	store := reading.NewStore(testPool)
	ctx := t.Context()

	book, err := store.Create(ctx, &reading.CreateParams{Title: "Sputnik Sweetheart", Author: "Murakami"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.CreateReflection(ctx, book.ID, nil, "a body to embed"); err != nil {
		t.Fatalf("CreateReflection: %v", err)
	}

	shelfDocs, err := reading.NewShelfEmbeddingSource(store).MissingEmbeddings(ctx, 10)
	if err != nil {
		t.Fatalf("shelf MissingEmbeddings: %v", err)
	}
	if len(shelfDocs) != 1 {
		t.Fatalf("shelf MissingEmbeddings = %d, want 1 (the seeded book has a NULL embedding)", len(shelfDocs))
	}
	if shelfDocs[0].Title != "Sputnik Sweetheart" || shelfDocs[0].Body != "Murakami" {
		t.Errorf("shelf doc = {Title:%q Body:%q}, want title + author", shelfDocs[0].Title, shelfDocs[0].Body)
	}

	reflDocs, err := reading.NewReflectionEmbeddingSource(store).MissingEmbeddings(ctx, 10)
	if err != nil {
		t.Fatalf("reflection MissingEmbeddings: %v", err)
	}
	if len(reflDocs) != 1 || reflDocs[0].Title != "a body to embed" {
		t.Fatalf("reflection MissingEmbeddings = %+v, want one doc carrying the body", reflDocs)
	}
}
