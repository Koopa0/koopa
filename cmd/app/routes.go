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
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/activity"
	"github.com/Koopa0/koopa/internal/agent"
	agentnote "github.com/Koopa0/koopa/internal/agent/note"
	agenttask "github.com/Koopa0/koopa/internal/agent/task"
	"github.com/Koopa0/koopa/internal/auth"
	"github.com/Koopa0/koopa/internal/bookmark"
	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/feed"
	"github.com/Koopa0/koopa/internal/feed/entry"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/learning/fsrs"
	"github.com/Koopa0/koopa/internal/learning/hypothesis"
	learningplan "github.com/Koopa0/koopa/internal/learning/plan"
	"github.com/Koopa0/koopa/internal/note"
	"github.com/Koopa0/koopa/internal/project"
	"github.com/Koopa0/koopa/internal/search"
	"github.com/Koopa0/koopa/internal/stats"
	"github.com/Koopa0/koopa/internal/systemhealth"
	"github.com/Koopa0/koopa/internal/tag"
	"github.com/Koopa0/koopa/internal/today"
	"github.com/Koopa0/koopa/internal/todo"
	"github.com/Koopa0/koopa/internal/topic"
	"github.com/Koopa0/koopa/internal/upload"
)

// handlers holds all handler dependencies for route registration.
type handlers struct {
	auth         *auth.Handler
	content      *content.Handler
	bookmark     *bookmark.Handler
	project      *project.Handler
	topic        *topic.Handler
	feed         *feed.Handler
	entry        *entry.Handler
	goal         *goal.Handler
	tag          *tag.Handler
	stats        *stats.Handler
	activity     *activity.Handler
	upload       *upload.Handler
	hypothesis   *hypothesis.Handler
	task         *agenttask.Handler
	agent        *agent.Handler
	daily        *daily.Handler
	learning     *learning.Handler
	note         *note.Handler
	todo         *todo.Handler
	plan         *learningplan.Handler
	fsrs         *fsrs.Handler
	agentNote    *agentnote.Handler
	today        *today.Handler
	search       *search.Handler
	systemHealth *systemhealth.Handler
	pool         *pgxpool.Pool
	logger       *slog.Logger
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
	// --- Health checks (no auth) ---
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
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
	mux.HandleFunc("GET /api/bookmarks", h.bookmark.PublicList)
	mux.HandleFunc("GET /api/bookmarks/{slug}", h.bookmark.PublicBySlug)
	mux.HandleFunc("GET /api/search", h.content.PublicSearch)
	mux.HandleFunc("GET /api/knowledge-graph", h.content.KnowledgeGraph)
	mux.HandleFunc("GET /api/feed/rss", h.content.RSS)
	mux.HandleFunc("GET /api/feed/sitemap", h.content.Sitemap)
	mux.HandleFunc("GET /api/topics", h.topic.List)
	mux.HandleFunc("GET /api/topics/{slug}", h.topic.BySlug)
	mux.HandleFunc("GET /api/projects", h.project.PublicList)
	mux.HandleFunc("GET /api/projects/{slug}", h.project.BySlug)
	mux.HandleFunc("GET /api/portfolio", h.project.PublicPortfolio)

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
	mux.Handle("POST /api/admin/knowledge/content/{id}/archive", adminMid(http.HandlerFunc(h.content.Archive)))
	mux.Handle("PATCH /api/admin/knowledge/content/{id}/is-public", adminMid(http.HandlerFunc(h.content.SetIsPublic)))

	// --- Admin: Knowledge / Bookmarks ---
	// URL is identity (bookmarks.url_hash UNIQUE) and is deliberately not
	// editable on the update path.
	mux.Handle("GET /api/admin/knowledge/bookmarks", authMid(http.HandlerFunc(h.bookmark.List)))
	mux.Handle("GET /api/admin/knowledge/bookmarks/{id}", authMid(http.HandlerFunc(h.bookmark.Get)))
	mux.Handle("POST /api/admin/knowledge/bookmarks", adminMid(http.HandlerFunc(h.bookmark.Create)))
	mux.Handle("PUT /api/admin/knowledge/bookmarks/{id}", adminMid(http.HandlerFunc(h.bookmark.Update)))
	mux.Handle("DELETE /api/admin/knowledge/bookmarks/{id}", adminMid(http.HandlerFunc(h.bookmark.Delete)))

	// --- Admin: Knowledge / Notes (Zettelkasten) ---
	// Maturity transitions go through their own endpoint so every maturity
	// change is auditable separately from field edits.
	mux.Handle("GET /api/admin/knowledge/notes", authMid(http.HandlerFunc(h.note.List)))
	mux.Handle("GET /api/admin/knowledge/notes/{id}", authMid(http.HandlerFunc(h.note.Get)))
	mux.Handle("POST /api/admin/knowledge/notes", adminMid(http.HandlerFunc(h.note.Create)))
	mux.Handle("PUT /api/admin/knowledge/notes/{id}", adminMid(http.HandlerFunc(h.note.Update)))
	mux.Handle("POST /api/admin/knowledge/notes/{id}/maturity", adminMid(http.HandlerFunc(h.note.Maturity)))
	mux.Handle("DELETE /api/admin/knowledge/notes/{id}", adminMid(http.HandlerFunc(h.note.Delete)))

	// --- Admin: Commitment / Projects ---
	// Full CRUD + profile variants for the public-portfolio facet.
	mux.Handle("GET /api/admin/commitment/projects", authMid(http.HandlerFunc(h.project.List)))
	mux.Handle("GET /api/admin/commitment/projects/{id}", authMid(http.HandlerFunc(h.project.Detail)))
	mux.Handle("POST /api/admin/commitment/projects", adminMid(http.HandlerFunc(h.project.Create)))
	mux.Handle("PUT /api/admin/commitment/projects/{id}", adminMid(http.HandlerFunc(h.project.Update)))
	mux.Handle("DELETE /api/admin/commitment/projects/{id}", adminMid(http.HandlerFunc(h.project.Delete)))

	// --- Admin: Commitment / Project profiles ---
	mux.Handle("GET /api/admin/commitment/projects/{id}/profile", authMid(http.HandlerFunc(h.project.GetProfile)))
	mux.Handle("PUT /api/admin/commitment/projects/{id}/profile", adminMid(http.HandlerFunc(h.project.UpsertProfile)))
	mux.Handle("DELETE /api/admin/commitment/projects/{id}/profile", adminMid(http.HandlerFunc(h.project.DeleteProfile)))

	// --- Admin: Commitment / Goals ---
	// List + Detail + status-transition. Create / Update stay off the REST
	// surface — goals are proposed through Cowork chat.
	mux.Handle("GET /api/admin/commitment/goals", authMid(http.HandlerFunc(h.goal.List)))
	mux.Handle("GET /api/admin/commitment/goals/{id}", authMid(http.HandlerFunc(h.goal.Detail)))
	mux.Handle("PUT /api/admin/commitment/goals/{id}/status", adminMid(http.HandlerFunc(h.goal.UpdateStatus)))

	// --- Admin: Commitment / Todos ---
	// State transitions route through POST /advance so each transition is a
	// distinct audit event separate from scalar field PUTs.
	mux.Handle("GET /api/admin/commitment/todos", authMid(http.HandlerFunc(h.todo.List)))
	mux.Handle("GET /api/admin/commitment/todos/{id}", authMid(http.HandlerFunc(h.todo.Get)))
	mux.Handle("POST /api/admin/commitment/todos", adminMid(http.HandlerFunc(h.todo.Create)))
	mux.Handle("PUT /api/admin/commitment/todos/{id}", adminMid(http.HandlerFunc(h.todo.Update)))
	mux.Handle("POST /api/admin/commitment/todos/{id}/advance", adminMid(http.HandlerFunc(h.todo.Advance)))
	mux.Handle("DELETE /api/admin/commitment/todos/{id}", adminMid(http.HandlerFunc(h.todo.Delete)))

	// --- Admin: Commitment / Today (aggregate) ---
	// Today pulls from content (review queue), hypothesis (unverified),
	// task (completed awaiting approval), daily plan, agent_notes (planning
	// note), fsrs (due reviews), feed / goal (warnings).
	mux.Handle("GET /api/admin/commitment/today", authMid(http.HandlerFunc(h.today.Today)))

	// --- Admin: Commitment / Daily plan ---
	// Per-date plan envelope — the raw daily_plan_items join consumed
	// directly by the Today HERO and legacy now-page dashboard. /today
	// is the richer aggregate; /daily-plan is the focused read.
	mux.Handle("GET /api/admin/commitment/daily-plan", authMid(http.HandlerFunc(h.daily.Plan)))

	// --- Admin: Knowledge / Topics ---
	// List is reachable as admin (same payload as the public /api/topics list)
	// for the content-editor picker.
	mux.Handle("GET /api/admin/knowledge/topics", authMid(http.HandlerFunc(h.topic.List)))
	mux.Handle("POST /api/admin/knowledge/topics", adminMid(http.HandlerFunc(h.topic.Create)))
	mux.Handle("PUT /api/admin/knowledge/topics/{id}", adminMid(http.HandlerFunc(h.topic.Update)))
	mux.Handle("DELETE /api/admin/knowledge/topics/{id}", adminMid(http.HandlerFunc(h.topic.Delete)))

	// --- Admin: Knowledge / Tags ---
	mux.Handle("GET /api/admin/knowledge/tags", authMid(http.HandlerFunc(h.tag.List)))
	mux.Handle("POST /api/admin/knowledge/tags", adminMid(http.HandlerFunc(h.tag.Create)))
	mux.Handle("PUT /api/admin/knowledge/tags/{id}", adminMid(http.HandlerFunc(h.tag.Update)))
	mux.Handle("DELETE /api/admin/knowledge/tags/{id}", adminMid(http.HandlerFunc(h.tag.Delete)))
	mux.Handle("POST /api/admin/knowledge/tags/merge", adminMid(http.HandlerFunc(h.tag.Merge)))

	// --- Admin: Knowledge / Tag aliases ---
	mux.Handle("GET /api/admin/knowledge/tag-aliases", authMid(http.HandlerFunc(h.tag.ListAliases)))
	mux.Handle("POST /api/admin/knowledge/tag-aliases/{id}/map", adminMid(http.HandlerFunc(h.tag.MapAlias)))
	mux.Handle("POST /api/admin/knowledge/tag-aliases/{id}/confirm", adminMid(http.HandlerFunc(h.tag.ConfirmAlias)))
	mux.Handle("POST /api/admin/knowledge/tag-aliases/{id}/reject", adminMid(http.HandlerFunc(h.tag.RejectAlias)))
	mux.Handle("DELETE /api/admin/knowledge/tag-aliases/{id}", adminMid(http.HandlerFunc(h.tag.DeleteAlias)))

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
	mux.Handle("POST /api/admin/knowledge/feed-entries/{id}/feedback", adminMid(http.HandlerFunc(h.entry.SubmitFeedback)))

	// --- Admin: Coordination / Activity ---
	// /activity is the domain-level audit feed; /activity/sessions surfaces
	// GitHub push events grouped for the rewind view.
	mux.Handle("GET /api/admin/coordination/activity", authMid(http.HandlerFunc(h.activity.Changelog)))
	mux.Handle("GET /api/admin/coordination/activity/sessions", authMid(http.HandlerFunc(h.activity.Sessions)))

	// --- Admin: System / Stats ---
	mux.Handle("GET /api/admin/system/stats", authMid(http.HandlerFunc(h.stats.Overview)))
	mux.Handle("GET /api/admin/system/stats/drift", authMid(http.HandlerFunc(h.stats.Drift)))
	mux.Handle("GET /api/admin/system/stats/learning", authMid(http.HandlerFunc(h.stats.Learning)))

	// --- Admin: System / Health ---
	// Served out of internal/systemhealth — the 4-domain envelope is a
	// cross-domain aggregate and lives in its own package so stats can
	// stay focused on the advanced admin dashboard aggregates.
	mux.Handle("GET /api/admin/system/health", authMid(http.HandlerFunc(h.systemHealth.Check)))

	// --- Admin: Search ---
	// Composed across content and note sources in internal/search; each
	// source gets an even slice of the limit so one kind cannot dominate
	// the result envelope.
	mux.Handle("GET /api/admin/search", authMid(http.HandlerFunc(h.search.Search)))

	// --- Admin: Upload ---
	if h.upload != nil {
		// Upload is intentionally on authMid (not adminMid): it writes to R2
		// storage only, no audited DB mutation. Wrapping in adminMid would
		// pin a pool connection and commit an empty tx for every upload.
		// If Upload later records a metadata row to an audited table,
		// promote back to adminMid AND plumb api.TxFromContext into the
		// handler so the binding actually flows to the write.
		mux.Handle("POST /api/admin/upload", authMid(http.HandlerFunc(h.upload.Upload)))
	}

	// --- Admin: Learning / Hypotheses ---
	mux.Handle("GET /api/admin/learning/hypotheses", authMid(http.HandlerFunc(h.hypothesis.List)))
	mux.Handle("GET /api/admin/learning/hypotheses/{id}", authMid(http.HandlerFunc(h.hypothesis.Get)))
	mux.Handle("GET /api/admin/learning/hypotheses/{id}/lineage", authMid(http.HandlerFunc(h.hypothesis.Lineage)))
	mux.Handle("POST /api/admin/learning/hypotheses/{id}/verify", adminMid(http.HandlerFunc(h.hypothesis.Verify)))
	mux.Handle("POST /api/admin/learning/hypotheses/{id}/invalidate", adminMid(http.HandlerFunc(h.hypothesis.Invalidate)))
	mux.Handle("POST /api/admin/learning/hypotheses/{id}/archive", adminMid(http.HandlerFunc(h.hypothesis.Archive)))
	mux.Handle("POST /api/admin/learning/hypotheses/{id}/evidence", adminMid(http.HandlerFunc(h.hypothesis.AddEvidence)))

	// --- Admin: Learning / Dashboard + concepts + sessions + plans + reviews ---
	// Dashboard is the aggregate landing endpoint; concepts / sessions /
	// plans are the domain-entity views; /reviews/:card_id is the FSRS
	// rating record.
	mux.Handle("GET /api/admin/learning/dashboard", authMid(http.HandlerFunc(h.learning.Dashboard)))
	mux.Handle("GET /api/admin/learning/concepts", authMid(http.HandlerFunc(h.learning.ConceptsList)))
	mux.Handle("GET /api/admin/learning/concepts/{slug}", authMid(http.HandlerFunc(h.learning.ConceptDetail)))
	mux.Handle("GET /api/admin/learning/sessions", authMid(http.HandlerFunc(h.learning.SessionsList)))
	mux.Handle("GET /api/admin/learning/sessions/{id}", authMid(http.HandlerFunc(h.learning.SessionDetail)))
	mux.Handle("POST /api/admin/learning/sessions", adminMid(http.HandlerFunc(h.learning.StartSession)))
	mux.Handle("POST /api/admin/learning/sessions/{id}/end", adminMid(http.HandlerFunc(h.learning.EndSession)))
	mux.Handle("POST /api/admin/learning/sessions/{id}/attempts", adminMid(http.HandlerFunc(h.learning.RecordAttempt)))
	mux.Handle("GET /api/admin/learning/plans", authMid(http.HandlerFunc(h.plan.List)))
	mux.Handle("GET /api/admin/learning/plans/{id}", authMid(http.HandlerFunc(h.plan.Detail)))
	mux.Handle("POST /api/admin/learning/plans/{id}/entries", adminMid(http.HandlerFunc(h.plan.AddEntries)))
	mux.Handle("PUT /api/admin/learning/plans/{id}/entries/{entry_id}", adminMid(http.HandlerFunc(h.plan.UpdateEntry)))
	mux.Handle("POST /api/admin/learning/reviews/{card_id}", adminMid(http.HandlerFunc(h.fsrs.Review)))

	// --- Admin: Coordination / Tasks ---
	// All mutation paths run under adminMid for actor tx binding so audit
	// triggers attribute task_messages / tasks writes to the caller agent.
	mux.Handle("GET /api/admin/coordination/tasks", authMid(http.HandlerFunc(h.task.List)))
	mux.Handle("GET /api/admin/coordination/tasks/open", authMid(http.HandlerFunc(h.task.Open)))
	mux.Handle("GET /api/admin/coordination/tasks/completed", authMid(http.HandlerFunc(h.task.Completed)))
	mux.Handle("GET /api/admin/coordination/tasks/{id}", authMid(http.HandlerFunc(h.task.Get)))
	mux.Handle("GET /api/admin/coordination/tasks/{id}/messages", authMid(http.HandlerFunc(h.task.Messages)))
	mux.Handle("GET /api/admin/coordination/tasks/{id}/artifacts", authMid(http.HandlerFunc(h.task.Artifacts)))
	mux.Handle("POST /api/admin/coordination/tasks", adminMid(http.HandlerFunc(h.task.Submit)))
	mux.Handle("POST /api/admin/coordination/tasks/{id}/reply", adminMid(http.HandlerFunc(h.task.Reply)))
	mux.Handle("POST /api/admin/coordination/tasks/{id}/request-revision", adminMid(http.HandlerFunc(h.task.RequestRevision)))
	mux.Handle("POST /api/admin/coordination/tasks/{id}/approve", adminMid(http.HandlerFunc(h.task.Approve)))
	mux.Handle("POST /api/admin/coordination/tasks/{id}/cancel", adminMid(http.HandlerFunc(h.task.Cancel)))

	// --- Admin: Coordination / Agents ---
	// Agents are registry-managed — the admin surface is read-only;
	// /:name/notes is the runtime log tab.
	mux.Handle("GET /api/admin/coordination/agents", authMid(http.HandlerFunc(h.agent.List)))
	mux.Handle("GET /api/admin/coordination/agents/{name}", authMid(http.HandlerFunc(h.agent.Get)))
	mux.Handle("GET /api/admin/coordination/agents/{name}/tasks", authMid(http.HandlerFunc(h.task.AgentTasks)))
	mux.Handle("GET /api/admin/coordination/agents/{name}/notes", authMid(http.HandlerFunc(h.agentNote.ListForAgent)))

	// --- Admin: Coordination / Process runs ---
	mux.Handle("GET /api/admin/coordination/process-runs", authMid(http.HandlerFunc(h.stats.ProcessRuns)))

	// (Goal Detail moved to /api/admin/commitment/goals/{id} above.)
	// (Daily Plan replaced by /api/admin/commitment/today aggregate.)

	// --- Admin: Learning / Summary ---
	// Lightweight 3-field cell-state envelope for surfaces that need
	// streak + due-review count without paying for the full dashboard
	// fan-out. Shares its aggregation query with /learning/dashboard.
	mux.Handle("GET /api/admin/learning/summary", authMid(http.HandlerFunc(h.learning.Summary)))
}
