/* koopa.admin — mock data, keyed to the brief's data shapes. */
window.K = {
  // GET /api/admin/commitment/today — wired brief(morning) shape. Lists are [], never null.
  today: {
    date: "Saturday, June 7 2026 · W23",
    plan_completion: { planned: 6, completed: 3, deferred: 1 },
    // committed_todos = the daily plan (Item shape)
    committed_todos: [
      { id: "p1", title: "Rewrite auth handler to stdlib net/http", project_id: "koopa-core", area: "Build", energy: "high", state: "done", position: 1 },
      { id: "p2", title: "Review claude-cowork TIL drafts (3 in queue)", project_id: "Content", area: "Knowledge", energy: "medium", state: "done", position: 2 },
      { id: "p3", title: "FSRS scheduler drift — write the failing test first", project_id: "koopa-learning", area: "Build", energy: "high", state: "done", position: 3 },
      { id: "p4", title: "Replication & consistency — read DDIA ch.5", project_id: null, area: "Learning", energy: "medium", state: "in_progress", position: 4 },
      { id: "p5", title: "Draft milestone breakdown for the Q3 goal", project_id: "koopa-core", area: "Commitment", energy: "medium", state: "todo", position: 5 },
      { id: "p7", title: "LC #76 minimum window substring — second attempt", project_id: null, area: "Learning", energy: "high", state: "todo", position: 6 },
    ],
    // PendingDetail = a todo + its project
    overdue_todos: [
      { id: "o1", title: "Reply to pgvector maintainer about HNSW ef_search", project: "koopa-core", energy: "low", due: "2d overdue", state: "todo" },
      { id: "o2", title: "Renew the Cloud Run min-instances decision", project: "infra", energy: "medium", due: "1d overdue", state: "todo" },
    ],
    today_todos: [
      { id: "t1", title: "File the FSRS card-drift audit note", project: "koopa-learning", energy: "medium", due: "today", state: "todo" },
      { id: "t2", title: "Triage the GTD inbox to empty", project: null, energy: "low", due: "today", state: "todo" },
    ],
    upcoming_todos: [
      { id: "u1", title: "Write the week-23 digest", project: "Content", energy: "low", due: "Jun 8", state: "todo" },
      { id: "u2", title: "Audit tag_aliases for orphaned topics", project: "koopa-core", energy: "low", due: "Jun 10", state: "todo" },
    ],
    active_goals: [
      { id: "g_01JX", title: "Ship koopa v1 to a stable, self-hostable release", status: "in_progress", area: "Build", progress: 0.45, milestones: "2/5" },
      { id: "g_02KP", title: "Reach interview-ready system-design fluency", status: "in_progress", area: "Learning", progress: 0.28, milestones: "1/4" },
    ],
    unverified_hypotheses: [
      { id: "h1", claim: "I reach for channels when a mutex is simpler — confusing ‘elegant’ with ‘correct’.", invalidation_condition: "Three consecutive concurrency drills where I pick the simplest primitive unprompted.", observed_date: "2026-06-02", created_by: "claude-cowork" },
      { id: "h2", claim: "Reading papers I don’t fully grasp still raises my ceiling within two weeks.", invalidation_condition: "A month of paper-reading with no measurable transfer to design drills.", observed_date: "2026-05-28", created_by: "human" },
    ],
    // active_session uses omitempty — absent (not null) when no session is open
    active_session: {
      title: "Replication & consistency",
      domain: "system-design",
      plan: "Designing Data-Intensive Apps",
      elapsed: "00:42:18",
      attempts: 2,
    },
    rss_highlights: [
      { title: "A decade of dynamic typing regrets at scale", url: "#", feed_name: "the-morning-paper", created_at: "2h ago", color: "var(--dot-build-log)" },
      { title: "Why HNSW beats IVF for low-recall regimes", url: "#", feed_name: "pgvector/discussions", created_at: "4h ago", color: "var(--dot-til)" },
      { title: "Go 1.24 range-over-func, finally", url: "#", feed_name: "golang-weekly", created_at: "6h ago", color: "var(--dot-article)" },
      { title: "The case against auto-carryover in task systems", url: "#", feed_name: "hn-frontpage", created_at: "8h ago", color: "var(--dot-essay)" },
    ],
  },

  goal: {
    id: "g_01JX",
    title: "Ship koopa v1 to a stable, self-hostable release",
    description: "A single-binary Go backend + SSR Angular frontend that I can deploy and trust to run my whole knowledge + learning workflow without babysitting. Stdlib-first, no DDD, no framework lock-in.",
    status: "in_progress",
    area: "Build",
    quarter: "Q3 2026",
    deadline: "2026-09-30",
    milestones: [
      { id: "m1", title: "Pipeline rewrite as a crawl flow", done: true },
      { id: "m2", title: "GTD list views + daily-plan write endpoints", done: true },
      { id: "m3", title: "Learning engine: FSRS + observations stable", done: false },
      { id: "m4", title: "Single-binary build + embedded SSR", done: false },
      { id: "m5", title: "Self-host docs + one-command deploy", done: false },
    ],
    projects: [
      { id: "pr1", name: "koopa-core", progress: 0.72, open: 8 },
      { id: "pr2", name: "koopa-learning", progress: 0.45, open: 12 },
      { id: "pr3", name: "infra & deploy", progress: 0.30, open: 5 },
    ],
    recent_activity: [
      { id: "a1", body: "<b>claude-code</b> opened PR #214 — embed SSR renderer in the Go binary", when: "2h ago", brand: true },
      { id: "a2", body: "Milestone <b>GTD list views</b> marked complete", when: "1d ago", brand: false },
      { id: "a3", body: "<b>claude-cowork</b> flagged FSRS drift on 6 cards after scheduler change", when: "2d ago", brand: false },
      { id: "a4", body: "Deadline moved from Sep 15 to <b>Sep 30</b>", when: "5d ago", brand: false },
    ],
  },

  // GET /learning/plans/{id} — real read-model envelope (de-embedded): { plan, entries, progress }
  // `attempts` is a sibling fetch (justifying attempts for the audit gate), kept here for the prototype.
  plan: {
    plan: {
      id: "lp_04A",
      title: "System design fluency — from patterns to tradeoffs",
      description: "Move from recognising patterns to reasoning about tradeoffs under real constraints. Anchored on DDIA + hands-on design drills, graded against my own observation log.",
      domain: "system-design",
      goal_id: "g_01JX",
      goal_name: "Ship koopa v1",
      status: "active",
      target_count: 9,
    },
    progress: { total: 9, completed: 3, skipped: 1, substituted: 1, remaining: 4 },
    entries: [
      { plan_entry_id: "pe1", learning_target_id: "lt_a", title: "Data models & query languages (DDIA ch.2)", position: 1, phase: "foundation", status: "completed", completed_by_attempt_id: "at1", reason: "Recalled the document-vs-relational tradeoff cleanly under question." },
      { plan_entry_id: "pe2", learning_target_id: "lt_b", title: "Storage & retrieval — LSM vs B-tree (DDIA ch.3)", position: 2, phase: "foundation", status: "completed", completed_by_attempt_id: "at1", reason: "Explained write-amplification without notes." },
      { plan_entry_id: "pe3", learning_target_id: "lt_c", title: "Encoding & evolution (DDIA ch.4)", position: 3, phase: "core", status: "substituted", substituted_by: "lt_c2" },
      { plan_entry_id: "pe4", learning_target_id: "lt_d", title: "Replication & consistency (DDIA ch.5)", position: 4, phase: "core", status: "active" },
      { plan_entry_id: "pe5", learning_target_id: "lt_e", title: "Partitioning & rebalancing (DDIA ch.6)", position: 5, phase: "core", status: "pending" },
      { plan_entry_id: "pe6", learning_target_id: "lt_f", title: "Design drill: URL shortener under 10k QPS", position: 6, phase: "applied", status: "pending" },
      { plan_entry_id: "pe7", learning_target_id: "lt_g", title: "Design drill: a rate limiter that survives restarts", position: 7, phase: "applied", status: "skipped", reason: "Covered ad hoc during the self-host work — no added signal." },
      { plan_entry_id: "pe8", learning_target_id: "lt_h", title: "Design drill: pgvector-backed semantic search", position: 8, phase: "applied", status: "pending" },
      { plan_entry_id: "pe9", learning_target_id: "lt_i", title: "Write-up: my tradeoff heuristics, with counter-examples", position: 9, phase: "mastery", status: "pending" },
    ],
    attempts: [
      { id: "at1", title: "Design review: koopa's own RSS ingestion fan-out", when: "3d ago", verdict: "passed", note: "Named the back-pressure tradeoff unprompted" },
      { id: "at2", title: "Whiteboard: replication topology for self-host", when: "1d ago", verdict: "passed", note: "Chose single-leader for operational simplicity" },
      { id: "at3", title: "Coach drill: quorum reads under partition", when: "5h ago", verdict: "partial", note: "Hand-wavy on read-repair timing" },
    ],
  },

  // GET /commitment/todos?state=&project=&… — single Item shape, filtered by view.
  // state enum: inbox · todo · in_progress · done · someday
  todos: [
    // — inbox (unclarified captures) —
    { id: "td_a1", title: "HN: 'Postgres is enough' — does our pgvector path still hold at 1M rows?", state: "inbox", created_by: "system", age: "18m", source: "hn-frontpage" },
    { id: "td_a2", title: "Idea: collapse the FSRS scheduler + observation writer into one transaction", state: "inbox", created_by: "human", age: "1h" },
    { id: "td_a3", title: "Ask claude-cowork to draft a til on range-over-func", state: "inbox", created_by: "human", age: "2h" },
    { id: "td_a4", title: "Bookmark: the morning paper on CRDT garbage collection", state: "inbox", created_by: "system", age: "3h", source: "rss" },
    { id: "td_a5", title: "Why does the SSR build pull in 40MB of locale data?", state: "inbox", created_by: "human", age: "5h" },
    { id: "td_a6", title: "Reconsider single-binary embed vs. sidecar for the renderer", state: "inbox", created_by: "human", age: "1d" },
    // — clarified, pending (state todo, has project) —
    { id: "td_b1", title: "Reply to pgvector maintainer about HNSW ef_search", state: "todo", project: "koopa-core", area: "Build", energy: "low", due: "2d overdue", priority: "high" },
    { id: "td_b2", title: "Write the failing test for FSRS card drift", state: "todo", project: "koopa-learning", area: "Build", energy: "high", due: "today", priority: "high", in_today: true },
    { id: "td_b3", title: "Renew the Cloud Run min-instances decision", state: "todo", project: "infra", area: "Build", energy: "medium", due: "1d overdue", priority: "medium" },
    { id: "td_b4", title: "Draft milestone breakdown for the Q3 goal", state: "todo", project: "koopa-core", area: "Commitment", energy: "medium", due: "Jun 9", priority: "medium", in_today: true },
    { id: "td_b5", title: "Curate the morning-paper backlog (14 unread)", state: "todo", project: null, area: "Knowledge", energy: "low", due: "Jun 10", priority: "low" },
    { id: "td_b6", title: "Audit tag_aliases for orphaned topics", state: "todo", project: "koopa-core", area: "Knowledge", energy: "low", due: null, priority: "low" },
    { id: "td_b7", title: "Spike: range-over-func in the crawl fan-out", state: "in_progress", project: "koopa-core", area: "Build", energy: "high", due: "today", priority: "high", in_today: true },
    // — someday —
    { id: "td_c1", title: "Learn enough Rust to judge if the hot path is worth rewriting", state: "someday", energy: "high" },
    { id: "td_c2", title: "A proper grain-shader instead of the noise SVG overlay", state: "someday", energy: "low" },
    { id: "td_c3", title: "Self-host a small LLM for offline classification", state: "someday", energy: "high" },
    { id: "td_c4", title: "Write the 'why koopa is not a blog' essay", state: "someday", energy: "medium" },
    // — recurring (recur_interval / recur_unit) —
    { id: "td_r1", title: "Daily LeetCode — one pattern, timed", state: "todo", recur: "1d", recur_bucket: "due_today", project: null, area: "Learning", energy: "high", due: "today" },
    { id: "td_r2", title: "Triage the GTD inbox to empty", state: "todo", recur: "1d", recur_bucket: "due_today", project: null, area: "Build", energy: "low", due: "today" },
    { id: "td_r3", title: "Weekly digest write-up", state: "todo", recur: "1w", recur_bucket: "overdue", project: "Content", area: "Knowledge", energy: "medium", due: "1d overdue" },
    { id: "td_r4", title: "Review FSRS due cards", state: "todo", recur: "1d", recur_bucket: "overdue", project: null, area: "Learning", energy: "medium", due: "2d overdue" },
    // — history (done) —
    { id: "td_h1", title: "Rewrite auth handler to stdlib net/http", state: "done", project: "koopa-core", completed_at: "today 11:20", energy: "high" },
    { id: "td_h2", title: "Review claude-cowork TIL drafts (3 in queue)", state: "done", project: "Content", completed_at: "today 10:48", energy: "medium" },
    { id: "td_h3", title: "FSRS scheduler drift — write the failing test first", state: "done", project: "koopa-learning", completed_at: "today 09:30", energy: "high" },
    { id: "td_h4", title: "Embed SSR renderer spike", state: "done", project: "koopa-core", completed_at: "yesterday", energy: "high" },
    { id: "td_h5", title: "Two-pointers cheatsheet cleanup", state: "done", project: null, completed_at: "yesterday", energy: "low" },
  ],

  domains: ["system-design", "go", "ai", "leetcode", "reading"],
  areas: ["Build", "Knowledge", "Learning", "Commitment", "Health"],
  quarters: ["2026-Q2", "2026-Q3", "2026-Q4", "2027-Q1"],
  goalsList: [
    { id: "g_01JX", title: "Ship koopa v1 to a stable, self-hostable release", status: "in_progress", area: "Build", quarter: "2026-Q3", milestones: 5, done: 2 },
    { id: "g_02KP", title: "Reach interview-ready system-design fluency", status: "in_progress", area: "Learning", quarter: "2026-Q3", milestones: 4, done: 1 },
    { id: "g_03LM", title: "Publish 24 pieces this year, topic-organised", status: "on_hold", area: "Knowledge", quarter: "2026-Q4", milestones: 3, done: 2 },
    { id: "g_04NR", title: "Sustainable training base — sub-3:30 marathon", status: "not_started", area: "Health", quarter: "2027-Q1", milestones: 4, done: 0 },
  ],

  // Knowledge — Content (type/status enums for the editor)
  content: [
    { id: "c_01JU", title: "Postgres EXPLAIN (ANALYZE, BUFFERS) explained", type: "til", status: "review", is_public: false, topic: "system-design", tags: ["postgres", "performance", "buffers"], slug: "pg-explain-buffers", updated: "4h", actor: "claude-cowork", quality_score: 8.2, words: 438 },
    { id: "c_01JQ", title: "Golang concurrency: goroutines & channels", type: "article", status: "published", is_public: true, topic: "go", tags: ["go", "concurrency"], slug: "go-concurrency", preview_slug: "go-concurrency-goroutines-channels", updated: "2d", actor: "human", quality_score: 9.1, words: 2140 },
    { id: "c_01JR", title: "The cost of auto-carryover", type: "essay", status: "published", is_public: true, topic: "system-design", tags: ["gtd", "design"], slug: "auto-carryover-cost", updated: "5d", actor: "human", quality_score: 8.8, words: 1620 },
    { id: "c_01JS", title: "Rewriting the pipeline as a crawl flow — day 3", type: "build-log", status: "draft", is_public: false, topic: "system-design", tags: ["pipeline", "crawl"], slug: "crawl-pipeline-day-3", updated: "1h", actor: "human", quality_score: null, words: 720 },
    { id: "c_01JZ", title: "On reading papers I do not understand yet", type: "essay", status: "draft", is_public: false, topic: "ai", tags: ["learning", "reading"], slug: "on-reading-papers", updated: "1d", actor: "human", quality_score: null, words: 980 },
    { id: "c_01JX", title: "Week 23 — pipeline rewrite, CKA prep", type: "digest", status: "archived", is_public: true, topic: "system-design", tags: ["weekly"], slug: "week-23", preview_slug: "week-23-digest", updated: "3w", actor: "human", quality_score: 7.9, words: 1100 },
  ],
  contentBody: `# Postgres EXPLAIN (ANALYZE, BUFFERS) explained

When you're staring at a slow query, \`EXPLAIN ANALYZE\` tells you what the planner thought and what actually happened. But the \`BUFFERS\` option — often forgotten — tells you what memory the query actually touched. That's often more useful than the plan shape itself.

## How to read it

\`\`\`sql
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT * FROM content WHERE topic_id = 42 ORDER BY published_at DESC LIMIT 20;
\`\`\`

Look for:
- \`shared hit\` — cache hits. You want most reads here.
- \`shared read\` — disk reads. A handful is fine; hundreds is a problem.
- \`temp written\` — query spilled to disk. Almost always means you need to bump \`work_mem\`.

## Tying it to the plan

The hit/read ratio on a \`Seq Scan\` is usually what pushes me toward adding an index. On an \`Index Scan\`, a high read count often points at a bad ordering.

> I used to read plans without BUFFERS for years. Now I never read them without it.`,

  // Knowledge — Note (kind/maturity enums for the editor)
  notes: [
    { id: "n_07A", slug: "csp-vs-mutex", title: "When CSP beats a mutex (and when it doesn't)", kind: "solve-note", maturity: "evergreen", updated: "2d", backlinks: 6, words: 540 },
    { id: "n_07B", slug: "fsrs-drift", title: "FSRS card drift after a scheduler change", kind: "debug-postmortem", maturity: "needs_revision", updated: "5h", backlinks: 2, words: 310 },
    { id: "n_07C", slug: "single-binary-decision", title: "Why single-binary embed over a sidecar renderer", kind: "decision-log", maturity: "stub", updated: "1d", backlinks: 4, words: 180 },
    { id: "n_07D", slug: "hnsw-ef-search", title: "HNSW ef_search vs build-time, in my own words", kind: "concept-note", maturity: "seed", updated: "3h", backlinks: 1, words: 90 },
    { id: "n_07E", slug: "ddia-ch5", title: "Replication topologies — reading note", kind: "reading-note", maturity: "evergreen", updated: "1w", backlinks: 8, words: 620 },
  ],
  noteBody: `# When CSP beats a mutex (and when it doesn't)

I keep reaching for channels when a mutex would be simpler. The honest rule, written down so I stop re-deriving it:

**Use a mutex when** you're guarding a small piece of shared state and the critical section is short. It's the boring, correct default.

**Use a channel when** ownership of the data *moves* between goroutines, or when you're modelling a pipeline / fan-out where back-pressure matters.

The trap is aesthetic: channels *feel* more "Go", so I pick them to feel clever, then pay for it in goroutine-leak debugging. Elegant is not the same as correct.

## Counter-example

The RSS fan-out genuinely wanted channels — the back-pressure is the point. The FSRS state guard did not; a mutex was three lines and unbreakable.`,

  // GET /learning/dashboard — multi-widget; backend degrades per-widget (.Warn, never whole-page)
  learning: {
    mastery_stages: [
      { id: "encounter", n: 9 }, { id: "investigate", n: 14 }, { id: "practice", n: 12 }, { id: "consolidate", n: 8 }, { id: "integrate", n: 5 },
    ],
    total_concepts: 48,
    avg_mastery: 0.54,
    streak: { current: 12, best: 23, this_week: 5, week: [3, 2, 0, 4, 1, 2, 3] },
    concepts: [
      { name: "two-pointers", kind: "pattern", domain: "leetcode", mastery: 0.78, stage: "consolidate", obs: 12, next: "tomorrow" },
      { name: "amortized-analysis", kind: "principle", domain: "leetcode", mastery: 0.91, stage: "integrate", obs: 9, next: "in 14d" },
      { name: "csp", kind: "principle", domain: "go", mastery: 0.66, stage: "practice", obs: 8, next: "in 2d" },
      { name: "tradeoff-analysis", kind: "skill", domain: "system-design", mastery: 0.72, stage: "consolidate", obs: 11, next: "in 5d" },
      { name: "constraint-analysis", kind: "skill", domain: "leetcode", mastery: 0.52, stage: "investigate", obs: 7, next: "in 3d" },
      { name: "mvcc-and-vacuum", kind: "pattern", domain: "system-design", mastery: 0.12, stage: "encounter", obs: 2, next: "today" },
    ],
    due_reviews: [
      { target: "LC #76 · Minimum window substring", domain: "leetcode", retention: 0.82, last: "3d ago" },
      { target: "Designing Data-Intensive Apps · ch.5", domain: "reading", retention: 0.67, last: "1w ago" },
      { target: "Design: URL shortener under 10k QPS", domain: "system-design", retention: 0.71, last: "4d ago" },
    ],
    observations: [
      { signal: "weakness", category: "approach-selection", body: "Reached for a channel where a mutex was simpler. Confused ‘elegant’ with ‘correct’.", domain: "go", concept: "csp", when: "2d ago" },
      { signal: "mastery", category: "state-transition", body: "Recognised the sliding-window shape inside 45s and committed without false starts.", domain: "leetcode", concept: "two-pointers", when: "5d ago" },
      { signal: "improvement", category: "tradeoff-analysis", body: "Named the HNSW ef_search / build-time separation before the coach prompted.", domain: "system-design", concept: "tradeoff-analysis", when: "1w ago" },
    ],
    weaknesses: [
      { name: "mvcc-and-vacuum", domain: "system-design", mastery: 0.12, signal: "2 weak observations, no recovery" },
      { name: "edge-case-handling", domain: "leetcode", mastery: 0.34, signal: "fails on boundary inputs under time pressure" },
      { name: "bottleneck-diagnosis", domain: "system-design", mastery: 0.41, signal: "jumps to caching before measuring" },
    ],
  },

};
