// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go covers the FK/CHECK → ErrInvalidInput classification on
// the feed write paths. A feed write whose url is not http(s)
// (chk_feed_url_scheme) or whose name is blank (chk_feed_name_not_blank) raises
// a check violation (23514) that must surface as feed.ErrInvalidInput — which
// the handler maps to HTTP 400 — instead of a wrapped error that
// api.HandleError would render as an opaque 500. mapWriteError is shared by
// CreateFeed and UpdateFeed, so the table drives both paths.
//
// Run with:
//
//	go test -tags=integration ./internal/feed/...
package feed_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/feed"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.NewPool()
	testPool = pool

	// feeds writes fire an audit trigger that writes activity_events.actor
	// (FK on agents). Seed the builtin registry so the fallback 'system' actor
	// is present.
	registry := agent.NewBuiltinRegistry()
	if _, err := agent.SyncToTable(context.Background(), registry, agent.NewStore(pool), nil, slog.Default()); err != nil {
		slog.Default().Error("agent.SyncToTable", "error", err)
		cleanup()
		os.Exit(1)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}

func truncate(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`TRUNCATE feeds, feed_topics, topics, activity_events CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// seedFeed inserts a valid feed row and returns its id, for the update-path
// cases that need an existing row to mutate.
func seedFeed(t *testing.T, url, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO feeds (url, name, schedule)
		 VALUES ($1, $2, 'daily') RETURNING id`,
		url, name,
	).Scan(&id); err != nil {
		t.Fatalf("seeding feed %q: %v", url, err)
	}
	return id
}

// TestIntegration_Feed_InvalidInput verifies the check-violation (23514) →
// ErrInvalidInput classification on both CreateFeed and UpdateFeed.
func TestIntegration_Feed_InvalidInput(t *testing.T) {
	truncate(t)
	store := feed.NewStore(testPool, slog.Default())
	ctx := t.Context()

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "create with non-http url (chk_feed_url_scheme 23514)",
			run: func() error {
				_, err := store.CreateFeed(ctx, &feed.CreateParams{
					URL:      "ftp://example.com/feed.xml",
					Name:     "Bad scheme",
					Schedule: feed.ScheduleDaily,
				})
				return err
			},
		},
		{
			name: "create with blank name (chk_feed_name_not_blank 23514)",
			run: func() error {
				_, err := store.CreateFeed(ctx, &feed.CreateParams{
					URL:      "https://example.com/blank-name.xml",
					Name:     "   ",
					Schedule: feed.ScheduleDaily,
				})
				return err
			},
		},
		{
			name: "update to non-http url (chk_feed_url_scheme 23514)",
			run: func() error {
				id := seedFeed(t, "https://example.com/update-url.xml", "Update url target")
				badURL := "javascript:alert(1)"
				_, err := store.UpdateFeed(ctx, id, &feed.UpdateParams{URL: &badURL})
				return err
			},
		},
		{
			name: "update to blank name (chk_feed_name_not_blank 23514)",
			run: func() error {
				id := seedFeed(t, "https://example.com/update-name.xml", "Update name target")
				blank := "   "
				_, err := store.UpdateFeed(ctx, id, &feed.UpdateParams{Name: &blank})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, feed.ErrInvalidInput) {
				t.Fatalf("err = %v, want feed.ErrInvalidInput", err)
			}
		})
	}
}

// fakeFetcher is a hand-written fake for the feed.ManualFetcher consumer
// interface. The real fetcher (collector) makes outbound HTTP, which is not
// containerizable; per rules/testing.md § Test Doubles a plain-struct fake of
// an existing consumer interface is allowed here. It is asserted on the
// handler's OUTPUT (the new_items count), never on call order.
type fakeFetcher struct {
	ids []uuid.UUID
	err error
}

func (f *fakeFetcher) FetchFeed(context.Context, *feed.Feed) ([]uuid.UUID, error) {
	return f.ids, f.err
}

// newFeedHandler wires a real *feed.Handler against the shared test pool.
func newFeedHandler(fetcher feed.ManualFetcher) *feed.Handler {
	return feed.NewHandler(feed.NewStore(testPool, slog.Default()), fetcher, slog.Default())
}

// serveAdmin runs an admin mutation request through api.ActorMiddleware
// (actor="human") into the handler, exactly like the production adminMid chain.
// Feed Create/Update need the per-request tx the middleware binds (atomic
// feed+feed_topics write) and the audit trigger reads koopa.actor from it.
func serveAdmin(t *testing.T, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	mid := api.ActorMiddleware(testPool, "human", slog.Default())
	rec := httptest.NewRecorder()
	mid(h).ServeHTTP(rec, req)
	return rec
}

// seedTopic inserts a topic and returns its id, for the topic_id parsing path.
func seedTopic(t *testing.T, slug, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO topics (slug, name) VALUES ($1, $2) RETURNING id`,
		slug, name,
	).Scan(&id); err != nil {
		t.Fatalf("seeding topic %q: %v", slug, err)
	}
	return id
}

// errEnvelope decodes the standard api error envelope.
func errEnvelope(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode error envelope: %v (body=%s)", err, body)
	}
	return env.Error.Code
}

// TestIntegration_FeedHandler_Create drives POST /api/admin/feeds through the
// real *feed.Handler + ActorMiddleware against a real store. It pins the
// topic_id parse path: a valid topic_id is written into feed_topics, a malformed
// topic_id is a 400 INVALID-form rejection before the store, and a well-formed
// but non-existent topic_id surfaces the FK (23503 → ErrTopicNotFound) as 400.
func TestIntegration_FeedHandler_Create(t *testing.T) {
	truncate(t)
	h := newFeedHandler(nil)
	topicID := seedTopic(t, "go", "Go")

	tests := []struct {
		name        string
		body        string
		wantStatus  int
		wantErrCode string
		// wantTopicLinked, when set, asserts exactly one feed_topics row exists
		// for the created feed after a 201.
		wantTopicLinked bool
	}{
		{
			name:            "valid topic_id is linked",
			body:            `{"url":"https://example.com/go.xml","name":"Go feed","schedule":"daily","topic_ids":["` + topicID.String() + `"]}`,
			wantStatus:      http.StatusCreated,
			wantTopicLinked: true,
		},
		{
			name:        "malformed topic_id is rejected before the store",
			body:        `{"url":"https://example.com/bad.xml","name":"Bad topic","schedule":"daily","topic_ids":["not-a-uuid"]}`,
			wantStatus:  http.StatusBadRequest,
			wantErrCode: "BAD_REQUEST",
		},
		{
			name:        "non-existent topic_id surfaces FK as 400",
			body:        `{"url":"https://example.com/missing.xml","name":"Missing topic","schedule":"daily","topic_ids":["` + uuid.New().String() + `"]}`,
			wantStatus:  http.StatusBadRequest,
			wantErrCode: "TOPIC_NOT_FOUND",
		},
		{
			name:        "invalid schedule rejected at handler",
			body:        `{"url":"https://example.com/yearly.xml","name":"Bad sched","schedule":"yearly"}`,
			wantStatus:  http.StatusBadRequest,
			wantErrCode: "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/admin/feeds", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := serveAdmin(t, h.Create, req)

			resp := rec.Result()
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("Create status = %d, want %d (body=%s)", resp.StatusCode, tt.wantStatus, body)
			}
			if tt.wantErrCode != "" {
				if code := errEnvelope(t, body); code != tt.wantErrCode {
					t.Errorf("Create error.code = %q, want %q (body=%s)", code, tt.wantErrCode, body)
				}
				return
			}
			if tt.wantTopicLinked {
				var env struct {
					Data struct {
						ID uuid.UUID `json:"id"`
					} `json:"data"`
				}
				if err := json.Unmarshal(body, &env); err != nil {
					t.Fatalf("decode create response: %v (body=%s)", err, body)
				}
				var n int
				if err := testPool.QueryRow(t.Context(),
					`SELECT COUNT(*) FROM feed_topics WHERE feed_id = $1 AND topic_id = $2`,
					env.Data.ID, topicID,
				).Scan(&n); err != nil {
					t.Fatalf("counting feed_topics: %v", err)
				}
				if n != 1 {
					t.Errorf("feed_topics rows for created feed = %d, want 1", n)
				}
			}
		})
	}
}

// TestIntegration_FeedHandler_Update pins the present-but-empty rejection
// asymmetry: a PUT carrying url:"" or name:"" is a 400 at the handler boundary
// (mirroring chk_feed_url_scheme / chk_feed_name_not_blank) instead of a 500 at
// the DB, while an omitted field leaves the value unchanged. It drives the real
// *feed.Handler + ActorMiddleware against a seeded feed.
func TestIntegration_FeedHandler_Update(t *testing.T) {
	truncate(t)
	h := newFeedHandler(nil)

	tests := []struct {
		name        string
		body        string
		wantStatus  int
		wantErrCode string
		// wantName, when non-empty, asserts the persisted name after a 200.
		wantName string
	}{
		{
			name:        "present-but-empty url is a 400",
			body:        `{"url":""}`,
			wantStatus:  http.StatusBadRequest,
			wantErrCode: "BAD_REQUEST",
		},
		{
			name:        "present-but-empty name is a 400",
			body:        `{"name":""}`,
			wantStatus:  http.StatusBadRequest,
			wantErrCode: "BAD_REQUEST",
		},
		{
			name:        "invalid schedule is a 400",
			body:        `{"schedule":"yearly"}`,
			wantStatus:  http.StatusBadRequest,
			wantErrCode: "BAD_REQUEST",
		},
		{
			name:       "omitted url, valid name change persists",
			body:       `{"name":"Renamed feed"}`,
			wantStatus: http.StatusOK,
			wantName:   "Renamed feed",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := seedFeed(t, "https://example.com/upd-"+strconv.Itoa(i)+".xml", "Update target")
			req := httptest.NewRequest(http.MethodPut, "/api/admin/feeds/"+id.String(), strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", id.String())
			rec := serveAdmin(t, h.Update, req)

			resp := rec.Result()
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("Update status = %d, want %d (body=%s)", resp.StatusCode, tt.wantStatus, body)
			}
			if tt.wantErrCode != "" {
				if code := errEnvelope(t, body); code != tt.wantErrCode {
					t.Errorf("Update error.code = %q, want %q (body=%s)", code, tt.wantErrCode, body)
				}
				// The seeded url must survive a rejected update.
				var url string
				if err := testPool.QueryRow(t.Context(), `SELECT url FROM feeds WHERE id = $1`, id).Scan(&url); err != nil {
					t.Fatalf("reading url after rejected update: %v", err)
				}
				if !strings.HasPrefix(url, "https://example.com/upd-") {
					t.Errorf("url changed to %q after a rejected update, want unchanged", url)
				}
				return
			}
			var name string
			if err := testPool.QueryRow(t.Context(), `SELECT name FROM feeds WHERE id = $1`, id).Scan(&name); err != nil {
				t.Fatalf("reading name after update: %v", err)
			}
			if name != tt.wantName {
				t.Errorf("persisted name = %q, want %q", name, tt.wantName)
			}
		})
	}
}

// TestIntegration_FeedHandler_Delete drives DELETE /api/admin/feeds/{id}: a
// valid id returns 204 and removes the row; a malformed id is a 400.
func TestIntegration_FeedHandler_Delete(t *testing.T) {
	truncate(t)
	h := newFeedHandler(nil)

	t.Run("valid id deletes the row", func(t *testing.T) {
		id := seedFeed(t, "https://example.com/del.xml", "Delete me")
		req := httptest.NewRequest(http.MethodDelete, "/api/admin/feeds/"+id.String(), http.NoBody)
		req.SetPathValue("id", id.String())
		rec := serveAdmin(t, h.Delete, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("Delete status = %d, want 204 (body=%s)", rec.Code, rec.Body.String())
		}
		var n int
		if err := testPool.QueryRow(t.Context(), `SELECT COUNT(*) FROM feeds WHERE id = $1`, id).Scan(&n); err != nil {
			t.Fatalf("counting feed after delete: %v", err)
		}
		if n != 0 {
			t.Errorf("feed rows after delete = %d, want 0", n)
		}
	})

	t.Run("malformed id is a 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/admin/feeds/not-a-uuid", http.NoBody)
		req.SetPathValue("id", "not-a-uuid")
		rec := serveAdmin(t, h.Delete, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Delete(bad id) status = %d, want 400", rec.Code)
		}
		if code := errEnvelope(t, rec.Body.Bytes()); code != "BAD_REQUEST" {
			t.Errorf("Delete(bad id) error.code = %q, want BAD_REQUEST", code)
		}
	})
}

// TestIntegration_FeedHandler_Fetch drives POST /api/admin/feeds/{id}/fetch
// through the real handler with a fake fetcher. The store reads the feed by id
// (real DB), then the handler returns the fetcher's new_items count. A 404 is
// returned when the feed id does not exist, exercising the real storeErrors map.
func TestIntegration_FeedHandler_Fetch(t *testing.T) {
	truncate(t)

	t.Run("existing feed returns fetcher item count", func(t *testing.T) {
		id := seedFeed(t, "https://example.com/fetch.xml", "Fetch me")
		h := newFeedHandler(&fakeFetcher{ids: []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/feeds/"+id.String()+"/fetch", http.NoBody)
		req.SetPathValue("id", id.String())
		rec := httptest.NewRecorder()
		h.Fetch(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Fetch status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				NewItems int `json:"new_items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode fetch response: %v (body=%s)", err, rec.Body.String())
		}
		if env.Data.NewItems != 3 {
			t.Errorf("new_items = %d, want 3", env.Data.NewItems)
		}
	})

	t.Run("unknown feed id is a 404", func(t *testing.T) {
		h := newFeedHandler(&fakeFetcher{})
		missing := uuid.New()
		req := httptest.NewRequest(http.MethodPost, "/api/admin/feeds/"+missing.String()+"/fetch", http.NoBody)
		req.SetPathValue("id", missing.String())
		rec := httptest.NewRecorder()
		h.Fetch(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("Fetch(unknown id) status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
		}
		if code := errEnvelope(t, rec.Body.Bytes()); code != "NOT_FOUND" {
			t.Errorf("Fetch(unknown id) error.code = %q, want NOT_FOUND", code)
		}
	})
}

// TestIntegration_Feed_IncrementFailure_AutoDisable proves the auto-disable
// invariant against real DB state: Store.IncrementFailure called exactly
// MaxConsecutiveFailures (5) times leaves the feed disabled with
// disabled_reason set, and the counter at the threshold. The fourth call must
// NOT yet disable — the boundary is the behavior under test, not just the final
// state.
func TestIntegration_Feed_IncrementFailure_AutoDisable(t *testing.T) {
	truncate(t)
	store := feed.NewStore(testPool, slog.Default())
	ctx := t.Context()

	id := seedFeed(t, "https://example.com/failing.xml", "Flaky feed")

	// readState reads the persisted auto-disable state.
	readState := func() (enabled bool, reason *string, failures int) {
		t.Helper()
		if err := testPool.QueryRow(ctx,
			`SELECT enabled, disabled_reason, consecutive_failures FROM feeds WHERE id = $1`, id,
		).Scan(&enabled, &reason, &failures); err != nil {
			t.Fatalf("reading feed state: %v", err)
		}
		return enabled, reason, failures
	}

	// After 4 failures (one below MaxConsecutiveFailures), the feed must still
	// be enabled with no disabled_reason — the threshold is not yet reached.
	for i := range 4 {
		if err := store.IncrementFailure(ctx, id, "fetch timeout"); err != nil {
			t.Fatalf("IncrementFailure #%d: %v", i+1, err)
		}
	}
	if enabled, reason, failures := readState(); !enabled || reason != nil || failures != 4 {
		t.Fatalf("after 4 failures: enabled=%v reason=%v failures=%d, want enabled=true reason=nil failures=4",
			enabled, reason, failures)
	}

	// The 5th failure reaches MaxConsecutiveFailures and must auto-disable.
	if err := store.IncrementFailure(ctx, id, "fetch timeout"); err != nil {
		t.Fatalf("IncrementFailure #5: %v", err)
	}
	enabled, reason, failures := readState()
	if enabled {
		t.Errorf("after 5 failures: enabled = true, want false (auto-disabled)")
	}
	if failures != 5 {
		t.Errorf("after 5 failures: consecutive_failures = %d, want 5", failures)
	}
	if reason == nil {
		t.Fatalf("after 5 failures: disabled_reason = nil, want a recorded reason")
	}
	if !strings.Contains(*reason, "5 consecutive failures") {
		t.Errorf("disabled_reason = %q, want it to mention 5 consecutive failures", *reason)
	}
}
