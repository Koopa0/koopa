//go:build integration

package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/auth"
	"github.com/koopa0/blog-backend/internal/feed/entry"
	"github.com/koopa0/blog-backend/internal/collector"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
	aiflow "github.com/koopa0/blog-backend/internal/ai"
	"github.com/koopa0/blog-backend/internal/ai/exec"
	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/notion"
	"github.com/koopa0/blog-backend/internal/pipeline"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/reconcile"
	"github.com/koopa0/blog-backend/internal/review"
	"github.com/koopa0/blog-backend/internal/server"
	"github.com/koopa0/blog-backend/internal/session"
	"github.com/koopa0/blog-backend/internal/stats"
	"github.com/koopa0/blog-backend/internal/tag"
	"github.com/koopa0/blog-backend/internal/task"
	"github.com/koopa0/blog-backend/internal/topic"
	"github.com/koopa0/blog-backend/internal/monitor"
	"github.com/koopa0/blog-backend/internal/upload"
)

const testJWTSecret = "test-secret-key-for-integration-tests"

// testServer sets up a PostgreSQL testcontainer, runs migrations,
// creates all stores/handlers, and returns an httptest.Server.
func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	ctx := t.Context()

	pgContainer, err := postgres.Run(ctx,
		"pgvector/pgvector:pg17",
		postgres.WithDatabase("blog_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("starting postgres container: %v", err)
	}
	t.Cleanup(func() {
		if err := pgContainer.Terminate(context.Background()); err != nil {
			t.Logf("terminating postgres container: %v", err)
		}
	})

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("getting connection string: %v", err)
	}

	// run migrations
	_, thisFile, _, _ := runtime.Caller(0)
	migrationsDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations")
	m, err := migrate.New("file://"+migrationsDir, "pgx5://"+connStr[len("postgres://"):])
	if err != nil {
		t.Fatalf("creating migrator: %v", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("running migrations: %v", err)
	}
	srcErr, dbErr := m.Close()
	if srcErr != nil {
		t.Fatalf("closing migration source: %v", srcErr)
	}
	if dbErr != nil {
		t.Fatalf("closing migration db: %v", dbErr)
	}

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("creating pool: %v", err)
	}
	t.Cleanup(pool.Close)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	authStore := auth.NewStore(pool)
	topicStore := topic.NewStore(pool)
	contentStore := content.NewStore(pool)
	projectStore := project.NewStore(pool)
	reviewStore := review.NewStore(pool)
	collectedStore := entry.NewStore(pool)
	monitorStore := monitor.NewStore(pool)
	feedStore := feed.NewStore(pool, logger)
	flowrunStore := exec.NewStore(pool)
	notionStore := notion.NewStore(pool)
	goalStore := goal.NewStore(pool)
	taskStore := task.NewStore(pool)
	statsStore := stats.NewStore(pool)
	activityStore := activity.NewStore(pool)
	tagStore := tag.NewStore(pool)
	sessionStore := session.NewStore(pool)

	// mock flows + runner for pipeline endpoints
	registry := aiflow.NewRegistry(
		aiflow.NewMockContentReview(),
		aiflow.NewMockContentPolish(),
		aiflow.NewMockDigestGenerate(),
		aiflow.NewMockBookmarkGenerate(),
	)
	alerter := exec.NewLogAlerter(logger)
	runner := exec.New(flowrunStore, registry, 1, alerter, logger)
	runner.Start(t.Context())
	t.Cleanup(runner.Stop)

	feedCollector := collector.New(collectedStore, feedStore, logger)

	contentSync := pipeline.NewContentSync(pool, contentStore, contentStore, nil, nil, runner, logger)
	webhookRouter := pipeline.NewWebhookRouter("", "", "", contentSync, logger)
	triggers := pipeline.NewTriggers(runner, logger)
	triggers.WithCollector(feedCollector, feedStore)
	pipelineHandler := pipeline.NewHandler(contentSync, webhookRouter, triggers, logger)

	notionClient := notion.NewClient("")

	deps := server.Deps{
		Auth:      auth.NewHandler(authStore, testJWTSecret, &auth.GoogleConfig{}, logger),
		Topic:     topic.NewHandler(topicStore, contentStore, nil, logger),
		Content:   content.NewHandler(contentStore, "http://localhost:8080", nil, nil, logger),
		Project:   project.NewHandler(projectStore, logger),
		Review:    review.NewHandler(reviewStore, logger),
		Collected: entry.NewHandler(collectedStore, logger),
		Tracking:  monitor.NewHandler(monitorStore, logger),
		Pipeline:  pipelineHandler,
		FlowRun: func() *exec.Handler {
			h := exec.NewHandler(flowrunStore, runner, logger)
			h.WithContentDeps(contentStore, contentStore)
			return h
		}(),
		Upload:       upload.NewHandler(nil, "test-bucket", "http://localhost", logger),
		Feed:         feed.NewHandler(feedStore, feedCollector, logger),
		Notion:       notion.NewHandler(notionClient, notionStore, nil, projectStore, goalStore, taskStore, runner, "", logger),
		Tag:          tag.NewHandler(tagStore, pool, logger),
		Session:      session.NewHandler(sessionStore, logger),
		Reconcile:    reconcile.NewHandler(reconcile.NewStore(pool), logger),
		NotionSource: notion.NewSourceHandler(notionStore, notionClient, nil, logger),
		Goal:         goal.NewHandler(goalStore, logger),
		Task:         task.NewHandler(taskStore, logger),
		Stats:        stats.NewHandler(statsStore, logger),
		Activity:     activity.NewHandler(activityStore, logger),
		Pool:         pool,
		Logger:       logger,
	}

	// build handler the same way server.Run does
	authMid := auth.Middleware(testJWTSecret)
	noopMid := func(next http.Handler) http.Handler { return next }
	mux := http.NewServeMux()
	server.RegisterRoutes(mux, deps, authMid, noopMid)

	return httptest.NewServer(mux)
}

// login generates a JWT access token directly (bypasses OAuth flow).
// The auth system now uses Google OAuth, so password-based login is no longer available.
func login(t *testing.T, _ string) string {
	t.Helper()
	claims := auth.Claims{
		Email: "admin@koopa0.dev",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "admin@koopa0.dev",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("signing test JWT: %v", err)
	}
	return signed
}

func doRequest(t *testing.T, method, url, body, token string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("executing request: %v", err)
	}
	return resp
}

func decodeBody(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
}

// --- Auth Tests ---

// TODO: TestAuthFlow disabled — auth system migrated from password login to Google OAuth.
// The old subtests tested /api/auth/login (password-based) which no longer exists.
// Rewrite these tests to cover the OAuth callback flow when test infrastructure
// supports mocking the Google OAuth exchange.
//
// Subtests that remain valid without OAuth (protected endpoint checks) are preserved below.

func TestAuthFlow(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	t.Run("protected endpoint without token", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/admin/stats", "", "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("protected endpoint with invalid token", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/admin/stats", "", "invalid-token")
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
	})
}

// --- Topic CRUD Tests ---

func TestTopicCRUD(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()
	token := login(t, ts.URL)

	var topicID string

	t.Run("create topic", func(t *testing.T) {
		body := `{"slug":"backend","name":"Backend Engineering","description":"Server-side development","sort_order":1}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/topics", body, token)
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("expected 201, got %d: %s", resp.StatusCode, b)
		}
		var result struct {
			Data struct {
				ID   string `json:"id"`
				Slug string `json:"slug"`
				Name string `json:"name"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		topicID = result.Data.ID
		if result.Data.Slug != "backend" {
			t.Errorf("slug = %q, want %q", result.Data.Slug, "backend")
		}
	})

	t.Run("create duplicate topic", func(t *testing.T) {
		body := `{"slug":"backend","name":"Duplicate","description":"test"}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/topics", body, token)
		resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("expected 409, got %d", resp.StatusCode)
		}
	})

	t.Run("list topics", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/topics", "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var result struct {
			Data []struct {
				Slug string `json:"slug"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		if len(result.Data) != 1 {
			t.Fatalf("expected 1 topic, got %d", len(result.Data))
		}
	})

	t.Run("get topic by slug", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/topics/backend", "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var result struct {
			Data struct {
				Topic struct {
					Slug string `json:"slug"`
					Name string `json:"name"`
				} `json:"topic"`
				Contents []any `json:"contents"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		if result.Data.Topic.Slug != "backend" {
			t.Errorf("slug = %q, want %q", result.Data.Topic.Slug, "backend")
		}
	})

	t.Run("get nonexistent topic", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/topics/nonexistent", "", "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", resp.StatusCode)
		}
	})

	t.Run("update topic", func(t *testing.T) {
		body := `{"name":"Backend Dev"}`
		resp := doRequest(t, http.MethodPut, ts.URL+"/api/admin/topics/"+topicID, body, token)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
		}
		var result struct {
			Data struct {
				Name string `json:"name"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		if result.Data.Name != "Backend Dev" {
			t.Errorf("name = %q, want %q", result.Data.Name, "Backend Dev")
		}
	})

	t.Run("delete topic", func(t *testing.T) {
		resp := doRequest(t, http.MethodDelete, ts.URL+"/api/admin/topics/"+topicID, "", token)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", resp.StatusCode)
		}

		// verify deleted
		get := doRequest(t, http.MethodGet, ts.URL+"/api/topics/backend", "", "")
		get.Body.Close()
		if get.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 after delete, got %d", get.StatusCode)
		}
	})
}

// --- Content CRUD Tests ---

func TestContentCRUD(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()
	token := login(t, ts.URL)

	// create a topic first
	topicResp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/topics",
		`{"slug":"go","name":"Go","description":"Go programming"}`, token)
	var topicResult struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, topicResp, &topicResult)
	topicID := topicResult.Data.ID

	var contentID string

	t.Run("create content", func(t *testing.T) {
		body := fmt.Sprintf(`{
			"slug":"go-concurrency-guide",
			"title":"Go Concurrency Guide",
			"body":"# Goroutines\nGo uses goroutines for concurrency.",
			"excerpt":"Learn Go concurrency patterns",
			"type":"article",
			"tags":["go","concurrency"],
			"reading_time":10,
			"topic_ids":["%s"]
		}`, topicID)
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/contents", body, token)
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("expected 201, got %d: %s", resp.StatusCode, b)
		}
		var result struct {
			Data struct {
				ID     string   `json:"id"`
				Slug   string   `json:"slug"`
				Type   string   `json:"type"`
				Status string   `json:"status"`
				Tags   []string `json:"tags"`
				Topics []struct {
					Slug string `json:"slug"`
				} `json:"topics"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		contentID = result.Data.ID
		if result.Data.Slug != "go-concurrency-guide" {
			t.Errorf("slug = %q, want %q", result.Data.Slug, "go-concurrency-guide")
		}
		if result.Data.Status != "draft" {
			t.Errorf("status = %q, want %q", result.Data.Status, "draft")
		}
		if diff := cmp.Diff([]string{"concurrency", "go"}, result.Data.Tags, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
			t.Errorf("tags mismatch (-want +got):\n%s", diff)
		}
		if len(result.Data.Topics) != 1 || result.Data.Topics[0].Slug != "go" {
			t.Errorf("topics = %v, want [{slug:go}]", result.Data.Topics)
		}
	})

	t.Run("create duplicate content slug", func(t *testing.T) {
		body := `{"slug":"go-concurrency-guide","title":"Dup","type":"article"}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/contents", body, token)
		resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("expected 409, got %d", resp.StatusCode)
		}
	})

	t.Run("list contents (empty for public, content is draft)", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/contents", "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var result struct {
			Data []any `json:"data"`
			Meta struct {
				Total int `json:"total"`
			} `json:"meta"`
		}
		decodeBody(t, resp, &result)
		if len(result.Data) != 0 {
			t.Errorf("expected 0 contents (draft), got %d", len(result.Data))
		}
	})

	t.Run("publish content", func(t *testing.T) {
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/contents/"+contentID+"/publish", "", token)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
		}
		var result struct {
			Data struct {
				Status      string  `json:"status"`
				PublishedAt *string `json:"published_at"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		if result.Data.Status != "published" {
			t.Errorf("status = %q, want %q", result.Data.Status, "published")
		}
		if result.Data.PublishedAt == nil {
			t.Error("published_at should be set")
		}
	})

	t.Run("list published contents", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/contents", "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var result struct {
			Data []struct {
				Slug string `json:"slug"`
			} `json:"data"`
			Meta struct {
				Total int `json:"total"`
				Page  int `json:"page"`
			} `json:"meta"`
		}
		decodeBody(t, resp, &result)
		if len(result.Data) != 1 {
			t.Fatalf("expected 1 content, got %d", len(result.Data))
		}
		if result.Data[0].Slug != "go-concurrency-guide" {
			t.Errorf("slug = %q, want %q", result.Data[0].Slug, "go-concurrency-guide")
		}
		if result.Meta.Total != 1 {
			t.Errorf("meta.total = %d, want 1", result.Meta.Total)
		}
	})

	t.Run("get content by slug", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/contents/go-concurrency-guide", "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var result struct {
			Data struct {
				Title string `json:"title"`
				Body  string `json:"body"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		if result.Data.Title != "Go Concurrency Guide" {
			t.Errorf("title = %q, want %q", result.Data.Title, "Go Concurrency Guide")
		}
	})

	t.Run("get content by type", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/contents/by-type/article", "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var result struct {
			Data []struct {
				Type string `json:"type"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		if len(result.Data) != 1 {
			t.Fatalf("expected 1 article, got %d", len(result.Data))
		}
	})

	t.Run("topic by slug returns contents", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/topics/go", "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var result struct {
			Data struct {
				Topic struct {
					Slug string `json:"slug"`
				} `json:"topic"`
				Contents []struct {
					Slug string `json:"slug"`
				} `json:"contents"`
			} `json:"data"`
			Meta struct {
				Total int `json:"total"`
			} `json:"meta"`
		}
		decodeBody(t, resp, &result)
		if result.Data.Topic.Slug != "go" {
			t.Errorf("topic.slug = %q, want %q", result.Data.Topic.Slug, "go")
		}
		if len(result.Data.Contents) != 1 {
			t.Fatalf("expected 1 content under topic, got %d", len(result.Data.Contents))
		}
		if result.Meta.Total != 1 {
			t.Errorf("meta.total = %d, want 1", result.Meta.Total)
		}
	})

	t.Run("search content", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/search?q=goroutines", "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var result struct {
			Data []struct {
				Slug string `json:"slug"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		if len(result.Data) != 1 {
			t.Fatalf("expected 1 search result, got %d", len(result.Data))
		}
	})

	t.Run("search with no query", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/search", "", "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
	})

	t.Run("update content", func(t *testing.T) {
		body := `{"title":"Updated Go Concurrency"}`
		resp := doRequest(t, http.MethodPut, ts.URL+"/api/admin/contents/"+contentID, body, token)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
		}
		var result struct {
			Data struct {
				Title string `json:"title"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		if result.Data.Title != "Updated Go Concurrency" {
			t.Errorf("title = %q, want %q", result.Data.Title, "Updated Go Concurrency")
		}
	})

	t.Run("delete content (soft)", func(t *testing.T) {
		resp := doRequest(t, http.MethodDelete, ts.URL+"/api/admin/contents/"+contentID, "", token)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", resp.StatusCode)
		}

		// should not appear in public list
		listResp := doRequest(t, http.MethodGet, ts.URL+"/api/contents", "", "")
		var listResult struct {
			Data []any `json:"data"`
		}
		decodeBody(t, listResp, &listResult)
		if len(listResult.Data) != 0 {
			t.Errorf("expected 0 after archive, got %d", len(listResult.Data))
		}
	})
}

// --- Project CRUD Tests ---

func TestProjectCRUD(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()
	token := login(t, ts.URL)

	var projectID string

	t.Run("create project", func(t *testing.T) {
		body := `{
			"slug":"koopa-blog",
			"title":"koopa0.dev",
			"description":"Personal knowledge engine",
			"role":"Full Stack Developer",
			"tech_stack":["Go","Angular","PostgreSQL"],
			"highlights":["AI Pipeline","SSR"],
			"featured":true,
			"sort_order":1
		}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/projects", body, token)
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("expected 201, got %d: %s", resp.StatusCode, b)
		}
		var result struct {
			Data struct {
				ID       string   `json:"id"`
				Slug     string   `json:"slug"`
				Featured bool     `json:"featured"`
				Tech     []string `json:"tech_stack"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		projectID = result.Data.ID
		if result.Data.Slug != "koopa-blog" {
			t.Errorf("slug = %q, want %q", result.Data.Slug, "koopa-blog")
		}
		if !result.Data.Featured {
			t.Error("featured should be true")
		}
		if diff := cmp.Diff([]string{"Go", "Angular", "PostgreSQL"}, result.Data.Tech); diff != "" {
			t.Errorf("tech_stack mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("list projects", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/projects", "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var result struct {
			Data []struct {
				Slug string `json:"slug"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		if len(result.Data) != 1 {
			t.Fatalf("expected 1 project, got %d", len(result.Data))
		}
	})

	t.Run("get project by slug", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/projects/koopa-blog", "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("update project", func(t *testing.T) {
		body := `{"description":"Updated description"}`
		resp := doRequest(t, http.MethodPut, ts.URL+"/api/admin/projects/"+projectID, body, token)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
		}
	})

	t.Run("delete project", func(t *testing.T) {
		resp := doRequest(t, http.MethodDelete, ts.URL+"/api/admin/projects/"+projectID, "", token)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", resp.StatusCode)
		}
	})
}

// --- RSS & Sitemap Tests ---

func TestFeedEndpoints(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()
	token := login(t, ts.URL)

	// create and publish content
	body := `{"slug":"rss-test","title":"RSS Test Article","body":"test body","excerpt":"test","type":"article","tags":[]}`
	resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/contents", body, token)
	var createResult struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeBody(t, resp, &createResult)
	pubResp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/contents/"+createResult.Data.ID+"/publish", "", token)
	pubResp.Body.Close()

	t.Run("rss feed", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/feed/rss", "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if ct != "application/rss+xml; charset=utf-8" {
			t.Errorf("content-type = %q, want rss+xml", ct)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !bytes.Contains(b, []byte("RSS Test Article")) {
			t.Error("rss feed should contain the published article title")
		}
	})

	t.Run("sitemap", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/feed/sitemap", "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if ct != "application/xml; charset=utf-8" {
			t.Errorf("content-type = %q, want xml", ct)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !bytes.Contains(b, []byte("rss-test")) {
			t.Error("sitemap should contain the published content slug")
		}
	})
}

// --- Tracking Topic CRUD Tests ---

func TestTrackingCRUD(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()
	token := login(t, ts.URL)

	var trackingID string

	t.Run("create tracking topic", func(t *testing.T) {
		body := `{"name":"Go Releases","keywords":["golang","go release"],"sources":["https://blog.golang.org"],"schedule":"0 */12 * * *"}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/tracking", body, token)
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("expected 201, got %d: %s", resp.StatusCode, b)
		}
		var result struct {
			Data struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		trackingID = result.Data.ID
	})

	t.Run("list tracking topics", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/admin/tracking", "", token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("update tracking topic", func(t *testing.T) {
		body := `{"name":"Go Release Tracker"}`
		resp := doRequest(t, http.MethodPut, ts.URL+"/api/admin/tracking/"+trackingID, body, token)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
		}
	})

	t.Run("delete tracking topic", func(t *testing.T) {
		resp := doRequest(t, http.MethodDelete, ts.URL+"/api/admin/tracking/"+trackingID, "", token)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", resp.StatusCode)
		}
	})
}

// --- Admin Stats Test ---

func TestAdminStats(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()
	token := login(t, ts.URL)

	resp := doRequest(t, http.MethodGet, ts.URL+"/api/admin/stats", "", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var result struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	decodeBody(t, resp, &result)
	if result.Data.Status != "ok" {
		t.Errorf("status = %q, want %q", result.Data.Status, "ok")
	}
}

// --- Pipeline Stubs Test ---

func TestPipelineStubs(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()
	token := login(t, ts.URL)

	// Endpoints still returning 501 (not yet implemented, JWT-protected)
	stubEndpoints := []string{
		"/api/admin/pipeline/sync",
		"/api/admin/pipeline/generate",
		"/api/webhook/obsidian",
	}

	for _, ep := range stubEndpoints {
		t.Run(ep, func(t *testing.T) {
			resp := doRequest(t, http.MethodPost, ts.URL+ep, "", token)
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotImplemented {
				t.Errorf("%s: expected 501, got %d", ep, resp.StatusCode)
			}
		})
	}

	// Notion webhook: HMAC-verified, returns 501 when no webhook secret configured
	t.Run("/api/webhook/notion_no_secret", func(t *testing.T) {
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/webhook/notion", "{}", "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("/api/webhook/notion: expected 501, got %d", resp.StatusCode)
		}
	})

	// Implemented endpoints: collect returns 202, digest returns 400 (missing dates)
	t.Run("/api/admin/pipeline/collect", func(t *testing.T) {
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/pipeline/collect", `{"schedule":"daily"}`, token)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("/api/admin/pipeline/collect: expected 202, got %d", resp.StatusCode)
		}
	})

	t.Run("/api/admin/pipeline/digest_missing_dates", func(t *testing.T) {
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/pipeline/digest", `{}`, token)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("/api/admin/pipeline/digest: expected 400, got %d", resp.StatusCode)
		}
	})
}

// --- Response Format Tests ---

func TestResponseFormat(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	t.Run("success response has data field", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/topics", "", "")
		var raw map[string]any
		decodeBody(t, resp, &raw)
		if _, ok := raw["data"]; !ok {
			t.Error("response missing 'data' field")
		}
	})

	t.Run("error response has error.code and error.message", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/contents/nonexistent", "", "")
		var raw struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		decodeBody(t, resp, &raw)
		if raw.Error.Code != "NOT_FOUND" {
			t.Errorf("error.code = %q, want %q", raw.Error.Code, "NOT_FOUND")
		}
		if raw.Error.Message == "" {
			t.Error("error.message should not be empty")
		}
	})

	t.Run("paginated response has meta", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/contents", "", "")
		var raw struct {
			Data any `json:"data"`
			Meta struct {
				Total      int `json:"total"`
				Page       int `json:"page"`
				PerPage    int `json:"per_page"`
				TotalPages int `json:"total_pages"`
			} `json:"meta"`
		}
		decodeBody(t, resp, &raw)
		if raw.Meta.Page != 1 {
			t.Errorf("meta.page = %d, want 1", raw.Meta.Page)
		}
		if raw.Meta.PerPage != 20 {
			t.Errorf("meta.per_page = %d, want 20", raw.Meta.PerPage)
		}
	})
}
