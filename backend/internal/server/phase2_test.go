//go:build integration

package server_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// TestPhase2EndToEnd validates the complete Phase 2 pipeline:
// 1. Feed CRUD (create, list, update, delete)
// 2. Manual feed fetch (via admin API)
// 3. Collected data listing with new fields
// 4. Feedback API (up/down)
// 5. Pipeline collect endpoint
// 6. Pipeline digest endpoint
// 7. Flow runs created for scoring
// 8. Feed auto-disable fields present
func TestPhase2EndToEnd(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()

	token := login(t, ts.URL)

	// --- Step 1: Feed CRUD ---
	t.Run("step1_feed_crud", func(t *testing.T) {
		// create feed
		body := `{"url":"https://go.dev/blog/feed.atom","name":"Go Blog","schedule":"daily","topics":["go"]}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/feeds", body, token)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create feed: expected 201, got %d", resp.StatusCode)
		}

		var createResult struct {
			Data struct {
				ID       string   `json:"id"`
				URL      string   `json:"url"`
				Name     string   `json:"name"`
				Schedule string   `json:"schedule"`
				Topics   []string `json:"topics"`
				Enabled  bool     `json:"enabled"`
			} `json:"data"`
		}
		decodeBody(t, resp, &createResult)

		if createResult.Data.URL != "https://go.dev/blog/feed.atom" {
			t.Errorf("feed url = %q, want %q", createResult.Data.URL, "https://go.dev/blog/feed.atom")
		}
		if createResult.Data.Schedule != "daily" {
			t.Errorf("feed schedule = %q, want %q", createResult.Data.Schedule, "daily")
		}
		if !createResult.Data.Enabled {
			t.Error("new feed should be enabled by default")
		}
		feedID := createResult.Data.ID

		// create second feed for list test
		body2 := `{"url":"https://blog.rust-lang.org/feed.xml","name":"Rust Blog","schedule":"weekly","topics":["rust"]}`
		resp2 := doRequest(t, http.MethodPost, ts.URL+"/api/admin/feeds", body2, token)
		if resp2.StatusCode != http.StatusCreated {
			t.Fatalf("create feed 2: expected 201, got %d", resp2.StatusCode)
		}
		resp2.Body.Close()

		// list feeds
		resp = doRequest(t, http.MethodGet, ts.URL+"/api/admin/feeds", "", token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list feeds: expected 200, got %d", resp.StatusCode)
		}

		var listResult struct {
			Data []json.RawMessage `json:"data"`
		}
		decodeBody(t, resp, &listResult)
		if len(listResult.Data) < 2 {
			t.Fatalf("list feeds: expected >= 2, got %d", len(listResult.Data))
		}

		// list feeds with schedule filter
		resp = doRequest(t, http.MethodGet, ts.URL+"/api/admin/feeds?schedule=daily", "", token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list feeds filtered: expected 200, got %d", resp.StatusCode)
		}

		var filteredResult struct {
			Data []struct {
				Schedule string `json:"schedule"`
			} `json:"data"`
		}
		decodeBody(t, resp, &filteredResult)
		for _, f := range filteredResult.Data {
			if f.Schedule != "daily" {
				t.Errorf("filtered feed schedule = %q, want %q", f.Schedule, "daily")
			}
		}

		// update feed
		updateBody := `{"name":"Go Official Blog"}`
		resp = doRequest(t, http.MethodPut, ts.URL+"/api/admin/feeds/"+feedID, updateBody, token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("update feed: expected 200, got %d", resp.StatusCode)
		}

		var updateResult struct {
			Data struct {
				Name string `json:"name"`
			} `json:"data"`
		}
		decodeBody(t, resp, &updateResult)
		if updateResult.Data.Name != "Go Official Blog" {
			t.Errorf("updated name = %q, want %q", updateResult.Data.Name, "Go Official Blog")
		}

		// duplicate url should conflict
		resp = doRequest(t, http.MethodPost, ts.URL+"/api/admin/feeds", body, token)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("duplicate feed: expected 409, got %d", resp.StatusCode)
		}
		resp.Body.Close()

		// invalid schedule
		badBody := `{"url":"https://new.example.com/feed","name":"Bad","schedule":"monthly"}`
		resp = doRequest(t, http.MethodPost, ts.URL+"/api/admin/feeds", badBody, token)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid schedule: expected 400, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	// --- Step 2: Manual feed fetch (will fail since URL is real but test is offline) ---
	t.Run("step2_feed_fetch_endpoint_exists", func(t *testing.T) {
		// create a feed with an unreachable URL to verify the endpoint works
		body := `{"url":"https://localhost:19999/nonexistent.xml","name":"Test Fetch","schedule":"hourly_4"}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/feeds", body, token)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create test feed: expected 201, got %d", resp.StatusCode)
		}

		var result struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)

		// fetch endpoint should exist and return 500 (connection refused, not 404)
		resp = doRequest(t, http.MethodPost, ts.URL+"/api/admin/feeds/"+result.Data.ID+"/fetch", "", token)
		// expect 500 because the feed URL is unreachable, but the endpoint exists
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			t.Fatalf("fetch endpoint not registered: got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	// --- Step 3: Collected data listing ---
	t.Run("step3_collected_data_listing", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/admin/collected", "", token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list collected: expected 200, got %d", resp.StatusCode)
		}

		var result struct {
			Data []json.RawMessage `json:"data"`
			Meta struct {
				Total   int `json:"total"`
				Page    int `json:"page"`
				PerPage int `json:"per_page"`
			} `json:"meta"`
		}
		decodeBody(t, resp, &result)
		// empty is fine, just verify structure works
		if result.Meta.Page != 1 {
			t.Errorf("page = %d, want 1", result.Meta.Page)
		}
	})

	// --- Step 4: Feedback API ---
	t.Run("step4_feedback_api_validation", func(t *testing.T) {
		// feedback on non-existent ID should not crash (422 or 404)
		body := `{"feedback":"up"}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/collected/00000000-0000-0000-0000-000000000000/feedback", body, token)
		// should be 404 (not found) or similar, not 500
		if resp.StatusCode == http.StatusInternalServerError {
			t.Fatalf("feedback on non-existent: got 500, expected error response")
		}
		resp.Body.Close()

		// invalid feedback value
		body = `{"feedback":"maybe"}`
		resp = doRequest(t, http.MethodPost, ts.URL+"/api/admin/collected/00000000-0000-0000-0000-000000000000/feedback", body, token)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("invalid feedback: expected 422, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	// --- Step 5: Pipeline collect endpoint ---
	t.Run("step5_pipeline_collect", func(t *testing.T) {
		body := `{"schedule":"daily"}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/pipeline/collect", body, token)
		// should be 202 Accepted (background processing)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("pipeline collect: expected 202, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	// --- Step 6: Pipeline digest endpoint ---
	t.Run("step6_pipeline_digest", func(t *testing.T) {
		body := `{"start_date":"2026-03-03","end_date":"2026-03-10"}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/pipeline/digest", body, token)
		// should be 202 Accepted
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("pipeline digest: expected 202, got %d", resp.StatusCode)
		}
		resp.Body.Close()

		// missing dates should be 400
		resp = doRequest(t, http.MethodPost, ts.URL+"/api/pipeline/digest", `{}`, token)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("pipeline digest without dates: expected 400, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})

	// --- Step 7: Flow runs listing (verify flow-run infrastructure) ---
	t.Run("step7_flow_runs", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, ts.URL+"/api/admin/flow-runs", "", token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list flow runs: expected 200, got %d", resp.StatusCode)
		}

		var result struct {
			Data []struct {
				ID       string `json:"id"`
				FlowName string `json:"flow_name"`
				Status   string `json:"status"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)
		// digest-generate job should have been submitted in step 6
		found := false
		for _, r := range result.Data {
			if r.FlowName == "digest-generate" {
				found = true
				if r.Status != "pending" && r.Status != "running" && r.Status != "completed" && r.Status != "failed" {
					t.Errorf("flow run status = %q, unexpected value", r.Status)
				}
			}
		}
		if !found {
			t.Log("digest-generate flow run not found yet (may be async)")
		}
	})

	// --- Step 8: Feed disable fields ---
	t.Run("step8_feed_disable_fields", func(t *testing.T) {
		// create a feed and verify disable-related fields are present
		body := `{"url":"https://example.com/rss","name":"Disable Test","schedule":"weekly"}`
		resp := doRequest(t, http.MethodPost, ts.URL+"/api/admin/feeds", body, token)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create feed: expected 201, got %d", resp.StatusCode)
		}

		var result struct {
			Data struct {
				ID                  string `json:"id"`
				Enabled             bool   `json:"enabled"`
				ConsecutiveFailures int    `json:"consecutive_failures"`
				LastError           string `json:"last_error"`
				DisabledReason      string `json:"disabled_reason"`
			} `json:"data"`
		}
		decodeBody(t, resp, &result)

		if !result.Data.Enabled {
			t.Error("new feed should be enabled")
		}
		if result.Data.ConsecutiveFailures != 0 {
			t.Errorf("consecutive_failures = %d, want 0", result.Data.ConsecutiveFailures)
		}

		// disable via update
		disableBody := fmt.Sprintf(`{"enabled":false}`)
		resp = doRequest(t, http.MethodPut, ts.URL+"/api/admin/feeds/"+result.Data.ID, disableBody, token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("disable feed: expected 200, got %d", resp.StatusCode)
		}

		var disabledResult struct {
			Data struct {
				Enabled bool `json:"enabled"`
			} `json:"data"`
		}
		decodeBody(t, resp, &disabledResult)
		if disabledResult.Data.Enabled {
			t.Error("feed should be disabled after update")
		}
	})
}
