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

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/koopa0/blog-backend/internal/auth"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/collector"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/flow"
	"github.com/koopa0/blog-backend/internal/flowrun"
	"github.com/koopa0/blog-backend/internal/notion"
	"github.com/koopa0/blog-backend/internal/pipeline"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/review"
	"github.com/koopa0/blog-backend/internal/server"
	"github.com/koopa0/blog-backend/internal/topic"
	"github.com/koopa0/blog-backend/internal/tracking"
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
	collectedStore := collected.NewStore(pool)
	trackingStore := tracking.NewStore(pool)
	feedStore := feed.NewStore(pool)
	flowrunStore := flowrun.NewStore(pool)

	// mock flows + runner for pipeline endpoints
	registry := flow.NewRegistry(
		flow.NewMockContentReview(),
		flow.NewMockContentPolish(),
		flow.NewMockCollectScore(),
		flow.NewMockDigestGenerate(),
		flow.NewMockBookmarkGenerate(),
	)
	alerter := flowrun.NewLogAlerter(logger)
	runner := flowrun.New(flowrunStore, registry, 1, alerter, logger)
	runner.Start(t.Context())
	t.Cleanup(runner.Stop)

	feedCollector := collector.New(collectedStore, feedStore, logger)

	pipelineHandler := pipeline.NewHandler(contentStore, nil, nil, runner, "", logger)
	pipelineHandler.SetCollector(feedCollector, feedStore)

	deps := server.Deps{
		Auth:      auth.NewHandler(authStore, testJWTSecret, logger),
		Topic:     topic.NewHandler(topicStore, contentStore, logger),
		Content:   content.NewHandler(contentStore, "http://localhost:8080", logger),
		Project:   project.NewHandler(projectStore, logger),
		Review:    review.NewHandler(reviewStore, logger),
		Collected: collected.NewHandler(collectedStore, logger),
		Tracking:  tracking.NewHandler(trackingStore, logger),
		Pipeline:  pipelineHandler,
		FlowRun:   flowrun.NewHandler(flowrunStore, logger),
		Flow:      flow.NewHandler(runner, nil, contentStore, contentStore, logger),
		Upload:    upload.NewHandler(nil, "test-bucket", "http://localhost", logger),
		Feed:      feed.NewHandler(feedStore, feedCollector, logger),
		Notion:    notion.NewHandler(notion.NewClient(""), projectStore, runner, notion.Config{}, logger),
		Logger:    logger,
	}

	// build handler the same way server.Run does
	authMid := auth.Middleware(testJWTSecret)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux, deps, authMid)

	return httptest.NewServer(mux)
}

// login authenticates as the seed admin user and returns an access token.
func login(t *testing.T, base string) string {
	t.Helper()
	body := `{"email":"admin@koopa0.dev","password":"changeme"}`
	resp := doRequest(t, http.MethodPost, base+"/api/auth/login", body, "")

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	decodeBody(t, resp, &result)
	if result.Data.AccessToken == "" {
		t.Fatal("login: empty access token")
	}
	return result.Data.AccessToken
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

func TestAuthFlow(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	t.Run("login with valid credentials", func(t *testing.T) {
		body := `{"email":"admin@koopa0.dev","password":"changeme"}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/auth/login", body, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var result struct {
			Data struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		if result.Data.AccessToken == "" {
			t.Error("access_token is empty")
		}
		if result.Data.RefreshToken == "" {
			t.Error("refresh_token is empty")
		}
	})

	t.Run("login with wrong password", func(t *testing.T) {
		body := `{"email":"admin@koopa0.dev","password":"wrong"}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/auth/login", body, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("login with missing fields", func(t *testing.T) {
		body := `{"email":"admin@koopa0.dev"}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/auth/login", body, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
	})

	t.Run("refresh token rotation", func(t *testing.T) {
		// login first
		loginBody := `{"email":"admin@koopa0.dev","password":"changeme"}`
		loginResp := doRequest(t, http.MethodPost, ts.URL+"/api/auth/login", loginBody, "")
		var loginResult struct {
			Data struct {
				RefreshToken string `json:"refresh_token"`
			} `json:"data"`
		}
		decodeBody(t, loginResp, &loginResult)

		// refresh
		refreshBody := fmt.Sprintf(`{"refresh_token":"%s"}`, loginResult.Data.RefreshToken)
		refreshResp := doRequest(t, http.MethodPost, ts.URL+"/api/auth/refresh", refreshBody, "")
		if refreshResp.StatusCode != http.StatusOK {
			t.Fatalf("refresh: expected 200, got %d", refreshResp.StatusCode)
		}
		var refreshResult struct {
			Data struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
			} `json:"data"`
		}
		decodeBody(t, refreshResp, &refreshResult)

		if refreshResult.Data.RefreshToken == loginResult.Data.RefreshToken {
			t.Error("refresh token was not rotated")
		}

		// old refresh token should be invalid
		reuse := doRequest(t, http.MethodPost, ts.URL+"/api/auth/refresh", refreshBody, "")
		reuse.Body.Close()
		if reuse.StatusCode != http.StatusUnauthorized {
			t.Fatalf("reuse old refresh token: expected 401, got %d", reuse.StatusCode)
		}
	})

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
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/contents/type/article", "", "")
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
		"/api/pipeline/sync",
		"/api/pipeline/generate",
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
	t.Run("/api/pipeline/collect", func(t *testing.T) {
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/pipeline/collect", `{"schedule":"daily"}`, token)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("/api/pipeline/collect: expected 202, got %d", resp.StatusCode)
		}
	})

	t.Run("/api/pipeline/digest_missing_dates", func(t *testing.T) {
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/pipeline/digest", `{}`, token)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("/api/pipeline/digest: expected 400, got %d", resp.StatusCode)
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
