// Copyright 2026 Koopa. All rights reserved.

// routes.go wires every HTTP route to its handler and chooses the right
// middleware shape per route. It is the one place that knows the full
// route table of the public API and admin API.
//
// Why this file is separate from middleware.go:
//   - middleware.go defines cross-cutting wrappers (recovery, CORS, …)
//   - routes.go decides, per route, whether a request needs JWT only
//     (authMid) or JWT + per-request actor tx (adminMid).
//
// Any new route goes here. Handler logic stays in the owning feature
// package (handler.go), never inline in this file.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/activity"
	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/auth"
	"github.com/Koopa0/koopa/internal/build"
	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/feed"
	"github.com/Koopa0/koopa/internal/feed/entry"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/project"
	"github.com/Koopa0/koopa/internal/search"
	"github.com/Koopa0/koopa/internal/stats"
	"github.com/Koopa0/koopa/internal/today"
	"github.com/Koopa0/koopa/internal/todo"
	"github.com/Koopa0/koopa/internal/topic"
)

// handlers holds all handler dependencies for route registration.
type handlers struct {
	auth     *auth.Handler
	content  *content.Handler
	project  *project.Handler
	topic    *topic.Handler
	feed     *feed.Handler
	entry    *entry.Handler
	goal     *goal.Handler
	stats    *stats.Handler
	activity *activity.Handler
	agent    *agent.Handler
	daily    *daily.Handler
	todo     *todo.Handler
	today    *today.Handler
	search   *search.Handler
	pool     *pgxpool.Pool
	logger   *slog.Logger

	// metricsHandler is mounted at GET /metrics by registerRoutes. The
	// MeterProvider itself is consumed via a local var in main.go (passed
	// to httpMetrics and background-goroutine constructors at wire time)
	// — no handler reads it from the struct, so it doesn't live here.
	metricsHandler http.Handler
}

// registerRoutes registers all API routes on the given mux.
//
// Two middleware shapes are used for admin routes:
//   - authMid — JWT validation only. Applied to read-only (GET) admin routes.
//   - adminMid — authMid composed with the actor middleware. Applied to
//     every admin mutation route (POST/PUT/PATCH/DELETE under /api/admin/).
//     The actor middleware opens a per-request tx and binds koopa.actor so
//     audit triggers record who mutated each row. Handlers MUST extract
//     the tx via api.TxFromContext and call store.WithTx(tx).<Mutation>
//     so the binding flows to the actual writes. A handler that forgets
//     degrades silently to the 'system' actor fallback — see
//     internal/api/middleware.go for the failure-mode contract.
func registerRoutes(
	mux *http.ServeMux,
	h *handlers,
	authMid func(http.Handler) http.Handler,
	adminMid func(http.Handler) http.Handler,
) {
	// --- Metrics scrape (no auth, no logging — see middleware.go::logging) ---
	// Mounted on its own route so VPS Prometheus job blog-backend can pull
	// the OTel SDK's Prometheus exposition. The handler comes from
	// setupObservability; when KOOPA_OBSERVABILITY_ENABLED=false it is
	// http.NotFoundHandler so /metrics returns 404 with no body.
	mux.Handle("GET /metrics", h.metricsHandler)

	// --- Health checks (no auth) ---
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_ = json.NewEncoder(w).Encode(struct {
			Status string     `json:"status"`
			Build  build.Info `json:"build"`
		}{Status: "ok", Build: build.Current()})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := h.pool.Ping(ctx); err != nil {
			h.logger.Error("readiness check failed", "error", err)
			http.Error(w, "db not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	})

	// --- Public API ---
	mux.HandleFunc("GET /api/contents", h.content.PublicList)
	mux.HandleFunc("GET /api/contents/{slug}", h.content.PublicBySlug)
	mux.HandleFunc("GET /api/contents/by-type/{type}", h.content.PublicByType)
	mux.HandleFunc("GET /api/contents/related/{slug}", h.content.PublicRelated)
	mux.HandleFunc("GET /api/search", h.content.PublicSearch)
	mux.HandleFunc("GET /api/knowledge-graph", h.content.KnowledgeGraph)
	mux.HandleFunc("GET /api/feed/rss", h.content.RSS)
	mux.HandleFunc("GET /api/feed/sitemap", h.content.Sitemap)
	mux.HandleFunc("GET /api/topics", h.topic.List)
	mux.HandleFunc("GET /api/topics/{slug}", h.topic.BySlug)

	// --- Auth ---
	if h.auth != nil {
		mux.HandleFunc("GET /api/auth/google", h.auth.GoogleLogin)
		mux.HandleFunc("GET /api/auth/google/callback", h.auth.GoogleCallback)
		mux.HandleFunc("POST /api/auth/refresh", h.auth.Refresh)
	}

	// --- Admin: Knowledge / Content ---
	// Lifecycle transitions (submit-for-review, revert-to-draft, archive) each
	// have their own endpoint so every status change surfaces as a distinct
	// audit event rather than riding a generic PUT.
	mux.Handle("GET /api/admin/knowledge/content", authMid(http.HandlerFunc(h.content.List)))
	mux.Handle("GET /api/admin/knowledge/content/{id}", authMid(http.HandlerFunc(h.content.Get)))
	mux.Handle("POST /api/admin/knowledge/content", adminMid(http.HandlerFunc(h.content.Create)))
	mux.Handle("PUT /api/admin/knowledge/content/{id}", adminMid(http.HandlerFunc(h.content.Update)))
	mux.Handle("DELETE /api/admin/knowledge/content/{id}", adminMid(http.HandlerFunc(h.content.Delete)))
	mux.Handle("POST /api/admin/knowledge/content/{id}/publish", adminMid(http.HandlerFunc(h.content.Publish)))
	mux.Handle("POST /api/admin/knowledge/content/{id}/submit-for-review", adminMid(http.HandlerFunc(h.content.SubmitForReview)))
	mux.Handle("POST /api/admin/knowledge/content/{id}/revert-to-draft", adminMid(http.HandlerFunc(h.content.RevertToDraft)))
	mux.Handle("POST /api/admin/knowledge/content/{id}/send-back", adminMid(http.HandlerFunc(h.content.SendBack)))
	mux.Handle("POST /api/admin/knowledge/content/{id}/archive", adminMid(http.HandlerFunc(h.content.Archive)))
	mux.Handle("PATCH /api/admin/knowledge/content/{id}/is-public", adminMid(http.HandlerFunc(h.content.SetIsPublic)))

	// --- Admin: Commitment / Projects ---
	mux.Handle("GET /api/admin/commitment/projects", authMid(http.HandlerFunc(h.project.List)))
	mux.Handle("GET /api/admin/commitment/projects/{id}", authMid(http.HandlerFunc(h.project.Detail)))
	mux.Handle("POST /api/admin/commitment/projects", adminMid(http.HandlerFunc(h.project.Create)))
	mux.Handle("PUT /api/admin/commitment/projects/{id}", adminMid(http.HandlerFunc(h.project.Update)))
	mux.Handle("DELETE /api/admin/commitment/projects/{id}", adminMid(http.HandlerFunc(h.project.Delete)))

	// --- Admin: Commitment / Goals ---
	// List + Detail + status-transition + the owner decision-stamp creates
	// (goal, milestone). Agents draft goals as inert proposals via propose_goal;
	// Koopa activates and creates milestones here in admin.
	// Areas back the goal-create/update area selector (PARA classification).
	mux.Handle("GET /api/admin/commitment/areas", authMid(http.HandlerFunc(h.goal.ListAreas)))
	mux.Handle("GET /api/admin/commitment/areas/{id}", authMid(http.HandlerFunc(h.goal.AreaDetail)))
	mux.Handle("POST /api/admin/commitment/areas", adminMid(http.HandlerFunc(h.goal.CreateArea)))
	mux.Handle("GET /api/admin/commitment/goals", authMid(http.HandlerFunc(h.goal.List)))
	mux.Handle("GET /api/admin/commitment/goals/{id}", authMid(http.HandlerFunc(h.goal.Detail)))
	mux.Handle("POST /api/admin/commitment/goals", adminMid(http.HandlerFunc(h.goal.Create)))
	mux.Handle("PUT /api/admin/commitment/goals/{id}", adminMid(http.HandlerFunc(h.goal.Update)))
	mux.Handle("PUT /api/admin/commitment/goals/{id}/status", adminMid(http.HandlerFunc(h.goal.UpdateStatus)))
	mux.Handle("POST /api/admin/commitment/goals/{id}/milestones", adminMid(http.HandlerFunc(h.goal.CreateMilestone)))
	mux.Handle("PUT /api/admin/commitment/goals/{id}/milestones/{mid}", adminMid(http.HandlerFunc(h.goal.UpdateMilestone)))
	mux.Handle("DELETE /api/admin/commitment/goals/{id}/milestones/{mid}", adminMid(http.HandlerFunc(h.goal.DeleteMilestone)))
	mux.Handle("POST /api/admin/commitment/goals/{id}/milestones/{mid}/toggle", adminMid(http.HandlerFunc(h.goal.ToggleMilestone)))

	// --- Admin: Commitment / Proposals triage ---
	// Agents propose inert goal/area drafts via MCP (propose_goal /
	// propose_area); the human reviews them here. Reads (count + list) are
	// authMid; activate (proposed → not_started/active) and reject (hard
	// DELETE; area reject cascades its proposed goals) are mutations → adminMid.
	mux.Handle("GET /api/admin/commitment/proposals", authMid(http.HandlerFunc(h.goal.Proposals)))
	mux.Handle("GET /api/admin/commitment/proposals/count", authMid(http.HandlerFunc(h.goal.ProposalsCount)))
	mux.Handle("POST /api/admin/commitment/goals/{id}/activate", adminMid(http.HandlerFunc(h.goal.ActivateGoal)))
	mux.Handle("DELETE /api/admin/commitment/goals/{id}/proposed", adminMid(http.HandlerFunc(h.goal.RejectGoal)))
	mux.Handle("POST /api/admin/commitment/areas/{id}/activate", adminMid(http.HandlerFunc(h.goal.ActivateArea)))
	mux.Handle("DELETE /api/admin/commitment/areas/{id}/proposed", adminMid(http.HandlerFunc(h.goal.RejectArea)))
	mux.Handle("POST /api/admin/commitment/projects/{id}/activate", adminMid(http.HandlerFunc(h.project.ActivateProject)))
	mux.Handle("DELETE /api/admin/commitment/projects/{id}/proposed", adminMid(http.HandlerFunc(h.project.RejectProject)))

	// --- Admin: Commitment / Todos ---
	// State transitions route through POST /advance so each transition is a
	// distinct audit event separate from scalar field PUTs.
	mux.Handle("GET /api/admin/commitment/todos", authMid(http.HandlerFunc(h.todo.List)))
	// recurring + history are literal sub-paths; Go 1.22 routing gives them
	// precedence over the {id} wildcard below.
	mux.Handle("GET /api/admin/commitment/todos/recurring", authMid(http.HandlerFunc(h.todo.Recurring)))
	mux.Handle("GET /api/admin/commitment/todos/history", authMid(http.HandlerFunc(h.todo.History)))
	mux.Handle("GET /api/admin/commitment/todos/{id}", authMid(http.HandlerFunc(h.todo.Get)))
	mux.Handle("POST /api/admin/commitment/todos", adminMid(http.HandlerFunc(h.todo.Create)))
	mux.Handle("PUT /api/admin/commitment/todos/{id}", adminMid(http.HandlerFunc(h.todo.Update)))
	mux.Handle("POST /api/admin/commitment/todos/{id}/advance", adminMid(http.HandlerFunc(h.todo.Advance)))
	mux.Handle("DELETE /api/admin/commitment/todos/{id}", adminMid(http.HandlerFunc(h.todo.Delete)))

	// --- Admin: Commitment / Today (aggregate) ---
	// Today is the HTTP mirror of brief(mode=morning): todo date views
	// (overdue / today / upcoming), the day's committed plan + completion
	// counts, active goals and RSS highlights.
	mux.Handle("GET /api/admin/commitment/today", authMid(http.HandlerFunc(h.today.Today)))

	// --- Admin: Commitment / Daily plan ---
	// Per-date plan envelope — the raw daily_plan_items join consumed
	// directly by the Today HERO and legacy now-page dashboard. /today
	// is the richer aggregate; /daily-plan is the focused read.
	mux.Handle("GET /api/admin/commitment/daily-plan", authMid(http.HandlerFunc(h.daily.Plan)))
	// Plan-write is the human equivalent of the MCP plan_day tool: it
	// idempotently replaces the date's planned rows in one tx and reports
	// the displaced todos. Mutation → adminMid (the per-request tx the
	// delete-then-insert and todo-state validation require).
	mux.Handle("PUT /api/admin/commitment/daily-plan", adminMid(http.HandlerFunc(h.daily.PutPlan)))

	// --- Admin: Knowledge / Topics ---
	// List is reachable as admin (same payload as the public /api/topics list)
	// for the content-editor picker.
	mux.Handle("GET /api/admin/knowledge/topics", authMid(http.HandlerFunc(h.topic.List)))
	mux.Handle("POST /api/admin/knowledge/topics", adminMid(http.HandlerFunc(h.topic.Create)))
	mux.Handle("PUT /api/admin/knowledge/topics/{id}", adminMid(http.HandlerFunc(h.topic.Update)))
	mux.Handle("DELETE /api/admin/knowledge/topics/{id}", adminMid(http.HandlerFunc(h.topic.Delete)))

	// --- Admin: Knowledge / Feeds ---
	// Fetch stays on authMid (not adminMid): it triggers the feed collector,
	// which runs multi-second HTTP I/O and writes via its own pool. Wrapping
	// in adminMid would pin a pool connection for the entire request and
	// commit an empty tx — pure waste. Collector writes record actor='system'
	// via the audit trigger fallback.
	if h.feed != nil {
		mux.Handle("GET /api/admin/knowledge/feeds", authMid(http.HandlerFunc(h.feed.List)))
		mux.Handle("POST /api/admin/knowledge/feeds", adminMid(http.HandlerFunc(h.feed.Create)))
		mux.Handle("PUT /api/admin/knowledge/feeds/{id}", adminMid(http.HandlerFunc(h.feed.Update)))
		mux.Handle("DELETE /api/admin/knowledge/feeds/{id}", adminMid(http.HandlerFunc(h.feed.Delete)))
		mux.Handle("POST /api/admin/knowledge/feeds/{id}/fetch", authMid(http.HandlerFunc(h.feed.Fetch)))
	}

	// --- Admin: Knowledge / Feed entries (triage) ---
	mux.Handle("GET /api/admin/knowledge/feed-entries", authMid(http.HandlerFunc(h.entry.List)))
	mux.Handle("POST /api/admin/knowledge/feed-entries/{id}/curate", adminMid(http.HandlerFunc(h.entry.Curate)))
	mux.Handle("POST /api/admin/knowledge/feed-entries/{id}/ignore", adminMid(http.HandlerFunc(h.entry.Ignore)))

	// --- Admin: System / Activity ---
	// /activity is the domain-level audit feed; /activity/sessions surfaces
	// GitHub push events grouped for the rewind view.
	mux.Handle("GET /api/admin/system/activity", authMid(http.HandlerFunc(h.activity.Changelog)))
	mux.Handle("GET /api/admin/system/activity/sessions", authMid(http.HandlerFunc(h.activity.Sessions)))

	// --- Admin: System / Stats ---
	mux.Handle("GET /api/admin/system/stats", authMid(http.HandlerFunc(h.stats.Overview)))
	mux.Handle("GET /api/admin/system/stats/drift", authMid(http.HandlerFunc(h.stats.Drift)))

	// --- Admin: System / Health ---
	// Served out of internal/stats — the snapshot consumed by the admin
	// shell (ribbon, today warnings, nav counters): feeds, pipelines,
	// database counts.
	mux.Handle("GET /api/admin/system/health", authMid(http.HandlerFunc(h.stats.Health)))

	// --- Admin: Search ---
	// Composed across content and note sources in internal/search; each
	// source gets an even slice of the limit so one kind cannot dominate
	// the result envelope.
	mux.Handle("GET /api/admin/search", authMid(http.HandlerFunc(h.search.Search)))

	// --- Admin: System / Agents ---
	// Agents are registry-managed — the admin surface is read-only.
	mux.Handle("GET /api/admin/system/agents", authMid(http.HandlerFunc(h.agent.List)))
	mux.Handle("GET /api/admin/system/agents/{name}", authMid(http.HandlerFunc(h.agent.Get)))

	// --- Admin: System / Process runs ---
	mux.Handle("GET /api/admin/system/process-runs", authMid(http.HandlerFunc(h.stats.ProcessRuns)))

	// (Goal Detail moved to /api/admin/commitment/goals/{id} above.)
	// (Daily Plan replaced by /api/admin/commitment/today aggregate.)
}
