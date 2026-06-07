/* koopa.dev — public reading site data. Shapes mirror content.Content / Topic / Project. */
window.SITE = {
  profile: {
    name: "Koopa",
    tagline: "A quiet instrument for thinking in public.",
    bio: "I build koopa — a semantic runtime for goals, learning and writing that several AI agents read from and write to. This is the published tip of that iceberg: notes, essays and build-logs, organised by idea, not by date.",
  },

  // GET /api/topics  → docs-style left nav source
  topics: [
    { slug: "system-design", name: "System design", description: "Tradeoffs under real constraints — storage, replication, the cost of convenience.", counts: { article: 3, essay: 2, "build-log": 2, til: 4 } },
    { slug: "go", name: "Go", description: "Stdlib-first, no frameworks. Concurrency you can reason about.", counts: { article: 2, til: 3, "build-log": 1 } },
    { slug: "ai", name: "AI & learning", description: "Agents, retrieval, spaced repetition, and learning how I learn.", counts: { article: 1, essay: 2, til: 2 } },
    { slug: "leetcode", name: "Problem solving", description: "Patterns, not memorisation. The 14 shapes that actually recur.", counts: { article: 1, til: 3 } },
  ],

  // GET /api/contents → published list (+ full body on detail)
  contents: [
    {
      slug: "go-concurrency-goroutines-channels", title: "Goroutines & channels, without the RxJS brain damage",
      type: "article", topic: "go", tags: ["go", "concurrency", "csp"], reading_time_min: 9, published_at: "2026-05-30", featured: true,
      excerpt: "Channels are not the answer to every concurrency problem in Go. The honest rule for when a mutex is simpler — and when ownership genuinely needs to move.",
      body: `Channels are the first thing people reach for when they learn Go's concurrency model. They feel like the *idiomatic* choice — the gopher way. But reaching for a channel when a mutex is simpler is one of the most common ways to write Go that is harder to debug than it needs to be.

## The honest rule

Use a **mutex** when you are guarding a small piece of shared state and the critical section is short. It is the boring, correct default. There is nothing un-idiomatic about \`sync.Mutex\` — the standard library is full of it.

Use a **channel** when ownership of the data *moves* between goroutines, or when you are modelling a pipeline or fan-out where back-pressure is the point.

> I used to pick channels to feel clever, then pay for it in goroutine-leak debugging. Elegant is not the same as correct.

## A concrete fan-out

The place a channel genuinely earned its keep was koopa's RSS ingestion. Feeds arrive at wildly different rates; the downstream classifier is the bottleneck. The back-pressure *is* the design:

\`\`\`go
func fanOut(feeds <-chan Feed, workers int) <-chan Item {
    out := make(chan Item)
    var wg sync.WaitGroup
    for i := 0; i < workers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for f := range feeds {
                for _, it := range f.Crawl() {
                    out <- it // blocks when the classifier is slow — good
                }
            }
        }()
    }
    go func() { wg.Wait(); close(out) }()
    return out
}
\`\`\`

The blocking send is not a bug to engineer around. It is the system telling the crawler to slow down because the classifier is saturated.

## Where I got it wrong

The FSRS scheduler state — a map of card IDs to review timestamps — did **not** want a channel. I wrapped it in a goroutine-with-a-channel "actor" because it felt clean. It was three times the code and leaked a goroutine on shutdown. A \`sync.Mutex\` and a plain map was three lines and unbreakable.

The test: does the data *move*, or is it *shared*? Moving data wants channels. Shared state wants a lock.`,
    },
    {
      slug: "auto-carryover-cost", title: "The cost of auto-carryover",
      type: "essay", topic: "system-design", tags: ["gtd", "design", "agency"], reading_time_min: 6, published_at: "2026-05-24", featured: true,
      excerpt: "Rolling an unfinished todo to tomorrow is convenient. It is also how a task system quietly erodes your relationship with your own commitments.",
      body: `Most task apps roll an unfinished todo forward automatically. You didn't do it today, so tomorrow it's there again, waiting. This is convenient. It is also, I think, a quiet mistake.

## Convenience that compounds the wrong way

When a todo carries itself over, the system makes a decision on your behalf: *this still matters, keep it.* But you never re-affirmed that. The commitment renews itself without your consent, and after a week you are staring at a list of things "you" decided were important — except you didn't, the defaults did.

> A system that makes decisions for you eventually makes you worse at making decisions yourself.

## What koopa does instead

In koopa, an unfinished daily-plan item does not silently reappear. At the end of the day it is **dropped from the plan**. If it still matters, you pull it back in tomorrow — a deliberate act that takes two seconds and re-affirms the commitment.

\`\`\`
PUT /commitment/daily-plan
{ "items": [{ "todo_id": "…", "position": 1 }] }   // you choose, every day
\`\`\`

The friction is the feature. It is small enough not to be annoying and large enough to keep you honest. The todo still exists — it's in Pending, it didn't evaporate — but it is no longer pretending to be today's problem until you say so.

## The general principle

Auto-carryover is one instance of a broader pattern: defaults that accumulate authority. Every convenience that removes a decision also removes a chance to notice you've changed your mind. For a personal system — one you'll live inside for years — preserving that noticing is worth a little friction.`,
    },
    {
      slug: "pg-explain-buffers", title: "Postgres EXPLAIN (ANALYZE, BUFFERS), read properly",
      type: "til", topic: "system-design", tags: ["postgres", "performance"], reading_time_min: 4, published_at: "2026-06-05",
      excerpt: "ANALYZE tells you what happened. BUFFERS tells you what memory the query actually touched — often the more useful number.",
      body: `When a query is slow, \`EXPLAIN ANALYZE\` tells you what the planner thought and what actually happened. But the \`BUFFERS\` option — often forgotten — tells you what memory the query actually touched. That's frequently more useful than the plan shape itself.

## How to read it

\`\`\`sql
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM content
WHERE topic_id = 42
ORDER BY published_at DESC LIMIT 20;
\`\`\`

Look for:

- \`shared hit\` — cache hits. You want most reads here.
- \`shared read\` — disk reads. A handful is fine; hundreds is a problem.
- \`temp written\` — the query spilled to disk. Almost always means you need more \`work_mem\`.

## Tying it back to the plan

The hit/read ratio on a \`Seq Scan\` is usually what pushes me toward an index. On an \`Index Scan\`, a high read count points at a bad ordering, not a missing index.

> I read plans without BUFFERS for years. Now I never read them without it.`,
    },
    {
      slug: "on-reading-papers", title: "On reading papers I don't understand yet",
      type: "essay", topic: "ai", tags: ["learning", "reading"], reading_time_min: 5, published_at: "2026-05-18",
      excerpt: "A defence of reading things slightly above your level — and a small ritual for doing it without bouncing off.",
      body: `There is a particular discomfort in reading a paper you don't fully grasp. The temptation is to close the tab and find something at your level. I've come to think that discomfort is the point.

## The ceiling moves in two weeks

My working hypothesis — written down so I can invalidate it — is that reading things slightly above my level raises my ceiling within about two weeks, even when I don't follow every step on the first pass. The mechanism isn't comprehension; it's *familiarity*. The second time I meet HNSW or MVCC, the shape is no longer foreign.

> The invalidation condition: a month of paper-reading with no measurable transfer to a design drill. If that happens, I'm wrong, and this ritual is procrastination with good PR.

## The ritual

1. One pass for *shape*, not detail — section headings, figures, the last paragraph of each section.
2. Mark the three sentences I'd need to understand to understand the rest.
3. Chase exactly those three. Not the whole paper. Three.

It keeps the discomfort bounded. I'm not trying to *finish* the paper; I'm trying to move my familiarity forward by one notch.`,
    },
    {
      slug: "crawl-pipeline-day-3", title: "Rewriting the pipeline as a crawl flow — day 3",
      type: "build-log", topic: "system-design", tags: ["pipeline", "crawl"], reading_time_min: 7, published_at: "2026-06-04",
      excerpt: "Day three of turning the ingestion pipeline into an explicit crawl flow. Back-pressure, idempotency, and one nasty fan-out bug.",
      body: `Day three of rebuilding ingestion as an explicit crawl flow rather than a tangle of cron jobs.

## What changed today

Made every stage **idempotent**, keyed on content hash. A re-run of a crawl no longer duplicates items — it upserts. This is what lets me retry aggressively without fear.

\`\`\`go
_, err := tx.Exec(ctx,
  \`INSERT INTO items (hash, payload) VALUES ($1, $2)
   ON CONFLICT (hash) DO NOTHING\`, h, p)
\`\`\`

## The bug

A goroutine leak in the fan-out: a worker blocked on a send to a channel nobody was draining after an early return. Classic. Fixed by deferring \`close\` behind a \`WaitGroup\` and never returning early from inside the select.

Tomorrow: wire the classifier's back-pressure into the crawl scheduler so a slow day doesn't blow the queue.`,
    },
    {
      slug: "week-23-digest", title: "Week 23 — pipeline rewrite, CKA prep",
      type: "digest", topic: "system-design", tags: ["weekly"], reading_time_min: 3, published_at: "2026-06-06",
      excerpt: "What I shipped, read and got wrong this week.",
      body: `A quiet, productive week.

## Shipped
- Pipeline rewrite reached idempotent crawl stages.
- GTD list views + the daily-plan write endpoint.

## Read
- DDIA ch.5 (replication) — finally internalised single-leader's operational case.

## Got wrong
- Reached for a channel where a mutex was simpler. Again. Wrote it down as an observation so the pattern stops being free.`,
    },
  ],

  // GET /api/projects(/{slug}) — the "let the work speak" surface
  projects: [
    {
      slug: "koopa", title: "koopa", role: "Solo — design, backend, frontend", featured: true,
      tech_stack: ["Go (stdlib-first)", "Postgres + pgvector", "Angular 22 SSR", "Genkit", "MCP"],
      description: "A personal knowledge & learning runtime that AI agents read from and write to. Not a blog, not a to-do app — a semantic instrument.",
      long_description: "koopa is a semantic runtime for one person's goals, projects, learning and writing. Several AI agents read its current state and write back through MCP — they don't remember what you said last week, they read what is true now. The public site is the selectively-published tip of that iceberg.",
      problem: "Most productivity tools either make decisions for you (auto-carryover, smart defaults) until you've outsourced your own judgement, or they're dumb stores that an LLM bolts onto. I wanted a system that preserves agency and gives agents a real, queryable model of my work — not a chat log.",
      solution: "A Go core exposing a typed domain (Goal ≠ Project ≠ Todo, Attempt ≠ Plan-completion, Observation ≠ Hypothesis) over both HTTP and MCP. Agents schedule against it; FSRS + a cognitive-observation log drive the learning engine; a crawl pipeline ingests and an editorial pipeline publishes.",
      architecture: "Single Go binary, stdlib net/http, no framework, no DDD ceremony. Postgres with pgvector for semantic search. SSR Angular embedded in the binary. Agents talk MCP; the same read-models serve the public site and the admin.",
      results: "Runs my whole daily workflow. ~48 tracked concepts under spaced repetition, a content pipeline that drafts → reviews → publishes, and a public site that's organised by idea, not date.",
      highlights: [
        "Idempotent crawl pipeline keyed on content hash — retry-safe by construction",
        "FSRS spaced-repetition + a cognitive-observation log that flags weakness patterns",
        "One domain model served over HTTP and MCP — agents and humans read the same truth",
        "Audit-gated learning: marking an entry complete requires the attempt that justifies it",
      ],
      github_url: "#", live_url: "#",
    },
    {
      slug: "fsrs-go", title: "fsrs-go", role: "Author", featured: false,
      tech_stack: ["Go"],
      description: "A small, dependency-free FSRS spaced-repetition scheduler in idiomatic Go.",
      long_description: "A clean-room implementation of the Free Spaced Repetition Scheduler in Go, with zero dependencies and a tiny surface area. Extracted from koopa's learning engine so others can use it.",
      problem: "Existing FSRS ports dragged in heavy dependencies or wrapped the algorithm in framework-shaped APIs. I wanted the scheduler as a value, not a service.",
      solution: "A single package: pass a card's state and a rating, get the next state and due date back. No I/O, no globals, no goroutines — a pure function you can test exhaustively.",
      highlights: [
        "Zero dependencies, ~400 lines",
        "Pure functions — trivially testable, no hidden state",
        "Used in production by koopa's review scheduler",
      ],
      github_url: "#",
    },
  ],
};
