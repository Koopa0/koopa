# Build Log — koopa0.dev Backend Phases

此文件記錄每個階段的實作狀態，避免 conversation compacting 導致上下文遺失。
每完成一個功能，必須在此更新狀態和驗收結果。

---

## Phase 1: Core Pipeline (完成)

| 項目 | 狀態 | 驗收 | 備註 |
|------|------|------|------|
| A1-A6: Schema changes | ✅ 完成 | migration 001 已部署 | |
| A2: CamelCase/snake_case splitting | ✅ 完成 | 單元測試通過 | |
| B1: Obsidian sync pipeline | ✅ 完成 | build/vet/lint/test 通過 | 含 activity_events 寫入 |
| B2: Self-loop protection | ✅ 完成 | 測試通過 | sender check |
| B3: GitHub diff stats | ✅ 完成 | 測試通過 | |
| B4: PR merge → Notion update | ✅ 完成 | build/vet/lint 通過 | regex + UUID format + maxNotionUpdatesPerPR=10 |
| B5: Frontmatter audit script | ✅ 完成 | | |
| C1: Genkit P0 fixes | ✅ 完成 | temperature + FinishReason | |
| C2: Genkit P1 prompt improvements | ✅ 完成 | | |
| D1: Daily Dev Log flow | ✅ 完成 | build/vet/lint 通過 | timezone fix: time.Date not Truncate |
| E1: Tag management (backend API) | ✅ 完成 | | |
| G1: Health check + Prometheus | ✅ 完成 | | |

### A: Schema & Parsing 細節

**A1-A6: 001_initial migration**
- 檔案: `migrations/001_initial.up.sql`, `001_initial.down.sql`
- 新增表: `obsidian_notes`, `obsidian_note_tags`, `activity_events`, `activity_event_tags`, `project_aliases`, `review_intervals`, `decision_logs`
- 索引: `search_vector` GIN, `idx_obsidian_notes_type`, `idx_obsidian_notes_context`, `idx_activity_events_timestamp`, `idx_activity_events_project`
- ENUM types: `project_status`, `content_status`

**A2: CamelCase/snake_case splitting**
- 檔案: `internal/obsidian/knowledge.go`
- 功能: 解析 Obsidian frontmatter，CamelCase/snake_case 轉換
- 測試: `internal/obsidian/knowledge_test.go` — table-driven tests

### B: Pipeline 細節

**B1: Obsidian sync pipeline**
- 檔案: `internal/pipeline/handler.go` (WebhookObsidian handler), `internal/note/store.go` (UpsertNote), `internal/activity/store.go` (CreateEvent)
- 流程: Obsidian webhook → parse frontmatter → upsert note → record activity event → tag linking
- 設計: content_hash 比對跳過未變更的筆記，best-effort activity recording

**B2: Self-loop protection**
- 檔案: `internal/pipeline/handler.go`
- 功能: GitHub webhook 檢查 sender 是否為 bot，避免自我觸發 loop
- 測試: `internal/pipeline/pipeline_test.go`

**B3: GitHub diff stats extraction**
- 檔案: `internal/pipeline/handler.go`, `internal/activity/activity.go` (DiffStats type)
- 功能: GitHub push webhook 解析 commits，計算 lines added/removed/files changed
- 存儲: metadata JSONB field in activity_events

**B4: PR merge → Notion Task update**
- 檔案: `internal/pipeline/handler.go` (handlePullRequest, handlePRMerge), `internal/notion/client.go` (UpdatePageStatus)
- 介面: `NotionTaskUpdater` (consumer-defined in pipeline), `SetNotionTaskUpdater` setter
- 邏輯: PR body 中 regex 提取 Notion URL → 32-char hex → 8-4-4-4-12 UUID format → PATCH Notion API
- 安全: `maxNotionUpdatesPerPR = 10` cap, pageID length validation (36 chars)
- 審查: security-reviewer 確認 HMAC 覆蓋完整, db-reviewer N/A

**B5: Frontmatter audit script**
- 檔案: `scripts/audit_frontmatter.sh`
- 功能: 掃描 Obsidian vault 驗證 frontmatter 完整性 (Stage 0 Gate)

### C: Genkit AI 細節

**C1: Genkit P0 fixes**
- 檔案: `internal/flow/content_review.go`
- 修復: `genai.Ptr[float32](0.3)` temperature (原本遺漏), `checkFinishReason` helper 檢查 LLM 回應完整性
- 影響: 所有 Genkit flow 使用統一的 finish reason 檢查

**C2: Genkit P1 prompt improvements**
- 檔案: `internal/flow/prompts/*.txt` (review, excerpt, tags, polish, digest, bookmark)
- 改進: 繁體中文 system prompt, 更精確的指令, 格式化要求

### D: Flows 細節

**D1: Daily Dev Log flow**
- 檔案: `internal/flow/daily_dev_log.go` (NEW), `internal/flow/prompts/daily_dev_log.txt` (NEW), `internal/flow/prompt.go` (embed), `internal/activity/query.sql` (EventsByTimeRange), `internal/activity/store.go` (EventsByTimeRange)
- 介面: `ActivityLister` (consumer-defined in flow package)
- 設計: 分組顯示 (GitHub/Obsidian/Other), 無事件時不呼叫 LLM, best-effort notification via Sender
- Bug fix: timezone — 使用 `time.Date(y, m, d-1, 0, 0, 0, 0, loc)` 而非 `Truncate(24*time.Hour)` (UTC-based 會導致 Asia/Taipei 錯誤)
- Cron: `0 23 * * *` Asia/Taipei
- 審查: go-reviewer 通過, db-reviewer 建議 `created_at` NOT NULL (deferred)

### E: Admin API 細節

**E1: Tag management backend**
- 檔案: `internal/tag/handler.go`, `internal/tag/store.go`, `internal/tag/query.sql`, `internal/tag/tag.go`
- Endpoints: CRUD for canonical tags + tag aliases
- 設計: `tag.Store` with pgx/v5, slug-based lookup, alias resolution

### G: Infrastructure 細節

**G1: Health check + Prometheus**
- 檔案: `internal/server/middleware.go` (health endpoint), `cmd/app/main.go` (prometheus handler)
- Endpoints: `GET /healthz`, `GET /metrics`
- Metrics: request duration histogram, request count by status/method

### Phase 1 關鍵設計決策
- **Consumer-defined interfaces**: 所有跨 package 依賴使用 consumer-side interface (e.g. `ActivityLister`, `NotionTaskUpdater`)
- **SetX setter pattern**: pipeline Handler 的可選依賴使用 setter 注入 (e.g. `SetNotionTaskUpdater`)
- **Best-effort pattern**: activity event recording, notifications 都是 log error + continue
- **Genkit Flow interface**: `Name() string` + `Run(ctx, json.RawMessage) (json.RawMessage, error)`, Registry 管理
- **Background processing**: `h.wg.Go(func() { ... })` for non-blocking webhook responses (return 202)

### Phase 1 待處理 (deferred)
- ~~`activity_events.created_at` NOT NULL~~ ✅ 已修正 (schema + store nil guard 移除)
- covering index on timestamp (低優先)
- rename PushRepository/PushSender to shared types (低優先)

---

## Phase 2: Knowledge Backbone

### MCP Server (最高優先)

| 項目 | 狀態 | 驗收 | 備註 |
|------|------|------|------|
| SQL queries: note search (text + filters) | ✅ 完成 | sqlc generate 成功 | SearchNotesByText, SearchNotesByFilters, NotesByTypeAndContext |
| SQL queries: activity filters | ✅ 完成 | sqlc generate 成功 | EventsByFilters, EventsByProject |
| SQL queries: project alias | ✅ 完成 | sqlc generate 成功 | ProjectByAlias via JOIN |
| note/store.go: search methods | ✅ 完成 | build 通過 | SearchByText, SearchByFilters, NotesByType |
| activity/store.go: filter methods | ✅ 完成 | build 通過 | EventsByFilters, EventsByProject |
| project/store.go: alias method | ✅ 完成 | build 通過 | ProjectByAlias |
| internal/mcp/mcp.go: types + RRF | ✅ 完成 | lint 通過 | NoteSearcher, ActivityReader, ProjectReader interfaces |
| internal/mcp/server.go: 4 tools | ✅ 完成 | lint 通過 | search_notes, get_project_context, get_recent_activity, get_decision_log |
| cmd/mcp/main.go: binary | ✅ 完成 | lint 通過 | stdio transport, pgxpool MaxConns=5 |
| MCP SDK dependency | ✅ 完成 | go mod tidy 成功 | github.com/modelcontextprotocol/go-sdk v1.4.1 |
| build/vet/lint | ✅ 通過 | 0 issues | |
| go test | ✅ 通過 | all pass | |
| go-reviewer | ✅ 通過 | all fixes applied | param rename, slices.SortFunc, best-effort comments |
| security-reviewer | ✅ 通過 | all fixes applied | input length validation, projectSummary type (omit NotionPageID) |
| db-reviewer | ✅ 通過 | deferred items noted | ProjectByAlias JOIN on title (known limitation, see below) |
| 二次 build/vet/lint | ✅ 通過 | 0 issues | 修復後重新驗證 |
| 二次 go test | ✅ 通過 | all pass | |

**MCP Server 設計決策:**
- Transport: stdio (separate binary `cmd/mcp/main.go`)
- Library: `github.com/modelcontextprotocol/go-sdk` (official)
- Package name: `mcpserver` (avoid collision with SDK `mcp` package)
- RRF: k=60, Go-side merge with tsvector + frontmatter exact match, slices.SortFunc
- No embedding for MVP
- sqlc.narg() for nullable filter params
- projectSummary response type (不暴露 NotionPageID)
- Input length validation: query max 500, filter max 100

**MCP Server 審查修復記錄:**
- go-reviewer: `clamp` params min/max → minVal/maxVal (避免 shadow Go 1.21 built-in)
- go-reviewer: insertion sort → `slices.SortFunc` (Go 1.21+ idiomatic)
- go-reviewer: `activities` → `activity` param name 一致
- go-reviewer: best-effort comments on nil assignments
- security-reviewer: input length validation (maxQueryLen=500, maxFilterLen=100)
- security-reviewer: `projectSummary` type 取代直接暴露 `project.Project`
- db-reviewer (deferred): ProjectByAlias JOIN on `p.title` — 設計限制，project_aliases.canonical_name 存 title 非 slug，未來需 migration 改為 project_id FK
- db-reviewer (deferred): LOWER(alias) 需 functional index — 小表目前可接受

### MCP Server 設計討論記錄

**Phase 2 MCP — comprehend agent 分析 (2026-03-17)**
- 5 個 blocking questions 被識別:
  1. Transport 選擇? → **stdio** (local-only, Claude Desktop/IDE 使用, 不需網路)
  2. Library 選擇? → **official `go-sdk`** (Anthropic 官方, 穩定)
  3. `decision_log` 的 type filter? → 用 `obsidian_notes.type = 'decision-log'`
  4. RRF 實作位置? → **Go-side** merge (tsvector + frontmatter exact match, 不依賴 pgvector)
  5. MVP 是否需要 embedding? → **No** (skip for MVP, 未來 Phase 加入)

**Phase 2 MCP — planner agent 設計 (2026-03-17)**
- 決定 4 個 tools: `search_notes`, `get_project_context`, `get_recent_activity`, `get_decision_log`
- RRF k=60, 3x over-fetch then merge
- `sqlc.narg()` for nullable filter params (原本用 `@filter::text` 生成 `string` 不是 `*string`, 修正後才能做 IS NULL check)
- 新增 6 個 SQL queries (3 note + 2 activity + 1 project), 不需 migration
- `project_aliases` JOIN 設計討論: canonical_name 存 title 而非 slug — db-reviewer 標記為風險, 但 schema 已部署, 改動需 migration, MVP 先保持

**Phase 2 MCP — 實作中發現的問題 (2026-03-17)**
- Package name collision: `internal/mcp` package name `mcp` 與 SDK import `github.com/modelcontextprotocol/go-sdk/mcp` 衝突 → 改用 `mcpserver`
- `cmd/mcp/main.go` gocritic `exitAfterDefer`: `defer stop()` 後面的 `os.Exit(1)` 會跳過 defer → 重構為 `run()` function pattern
- Security review 發現 `project.Project` 直接序列化會暴露 `NotionPageID` → 新增 `projectSummary` response type
- Security review 建議 input length validation → 新增 `maxQueryLen=500`, `maxFilterLen=100`
- Go-reviewer 發現 `min`/`max` params shadow Go 1.21 built-in → rename to `minVal`/`maxVal`
- Go-reviewer 建議 insertion sort → `slices.SortFunc` (Go 1.21+ idiomatic, N 可達 150)

**Phase 1 — 關鍵設計討論回顧**

*B4: PR merge → Notion update*
- 討論: 如何從 PR body 提取 Notion page ID? → regex `https?://(?:www\.)?notion\.so/\S*?([0-9a-f]{32})\b`
- 討論: 32-char hex 如何轉 UUID? → 手動格式化 8-4-4-4-12
- Security review: 無限制的 Notion API 呼叫 → 加 `maxNotionUpdatesPerPR = 10` cap
- Security review: `UpdatePageStatus` 未驗證 pageID → 加 `len(pageID) != 36` check

*D1: Daily Dev Log*
- 討論: 昨天的定義? → 使用 `time.Date(y, m, d-1, 0, 0, 0, 0, loc)` 而非 `now.Add(-24h).Truncate(24h)` — 後者是 UTC-based, Asia/Taipei (UTC+8) 會得到錯誤的 24 小時窗口
- 討論: events 過多怎辦? → planner 建議 priority-based top 30, 實作改用 source-based grouping (日常事件量不大)
- 討論: `activityStore` 宣告位置 → 需移到 main.go AI pipeline section 之前 (原本在 pipeline handler wiring 附近, D1 flow 更早需要)
- db-reviewer: `activity_events.created_at` 是 nullable (`*time.Time`) 但 domain Event.CreatedAt 是 `time.Time` → nil guard 修正, 建議未來加 NOT NULL

*B1: Obsidian sync*
- 討論: content_hash 比對策略 → SHA-256 of content, skip upsert if hash unchanged
- 討論: activity event dedup → `ON CONFLICT (source, event_type, source_id) WHERE source_id IS NOT NULL`
- 討論: tag linking → best-effort, first error captured, continue processing rest

---

### Genkit P2: Flow Split

| 項目 | 狀態 | 驗收 | 備註 |
|------|------|------|------|
| content-proofread sub-flow | ✅ 完成 | build/vet/lint 0 issues | pure: text in → ReviewResult out |
| content-excerpt sub-flow | ✅ 完成 | build/vet/lint 0 issues | pure: text in → excerpt string out |
| content-tags sub-flow | ✅ 完成 | build/vet/lint 0 issues | pure: text + topic list in → filtered tags out |
| content-review → thin orchestrator | ✅ 完成 | tests pass | calls sub-flows, handles persistence |
| Sub-flows registered in Registry | ✅ 完成 | | 可獨立執行 via flow runner |
| Mock mode updated | ✅ 完成 | | 3 new mock constructors |
| go-reviewer | ✅ 通過 | all fixes applied | error wrapping, map[string]struct{}, json.Marshal comment |
| security-reviewer | ✅ 通過 | all fixes applied | tag rejection warning, prompt body truncation (50k runes) |
| 二次 build/vet/lint | ✅ 通過 | 0 issues | |
| 二次 go test | ✅ 通過 | all pass | |

**P2 Flow Split 設計決策:**
- Sub-flows are pure: no DB deps, take text input, return typed output
- Orchestrator fetches content, calls sub-flows (typed .run()), handles persistence
- `ReviewResult` = type alias for `ContentProofreadOutput` (backward compat for cmd/calibrate, flowrun tests)
- Embedding + reading-time stay in orchestrator (not LLM flows, no sub-flow value)
- `truncateBodyRunes(50000)` caps prompt input length for token safety
- Tags sub-flow logs Warn when all LLM suggestions rejected by allowlist

**P2 Flow Split 審查修復記錄:**
- go-reviewer: "generating excerpt: generating excerpt:" double wrap → inner changed to "calling llm:"
- go-reviewer: `map[string]bool` → `map[string]struct{}` in tags filter
- go-reviewer: `json.Marshal` ignored error → added best-effort comment
- go-reviewer: registry call 160+ chars → multi-line
- security-reviewer: all tags rejected silently → added Warn log
- security-reviewer: unbounded prompt body → added `truncateBodyRunes(50000)` guard
- go-reviewer (deferred): concrete sub-flow types in orchestrator — intentional for typed I/O, dual path documented

### Spaced Repetition (SM-2)

| 項目 | 狀態 | 驗收 | 備註 |
|------|------|------|------|
| Schema: spaced_intervals table | ✅ 完成 | 加入 001_initial.up.sql | PK=note_id FK→obsidian_notes, partial index on due_at |
| SM-2 algorithm (pure function) | ✅ 完成 | 10 table-driven tests 全通過 | EF clamping, quality clamping, rep reset on q<3 |
| sqlc queries (4) | ✅ 完成 | sqlc generate 成功 | DueIntervals, IntervalByNoteID, UpsertInterval, InsertInterval |
| store.go | ✅ 完成 | build 通過 | DueIntervals, Interval, UpsertInterval, InsertInterval, DueCount |
| handler.go (3 endpoints) | ✅ 完成 | build/vet/lint 0 issues | ListDue, SubmitReview, Enroll |
| spaced_test.go | ✅ 完成 | 10/10 tests pass | cmpopts.EquateApprox for float comparison |
| Routes + main.go wiring | ✅ 完成 | build 通過 | 3 admin routes under /api/admin/spaced/ |
| go-reviewer v2.0 | ✅ 通過 | all fixes applied | errors.Is for sentinel, UpsertParams moved to spaced.go |
| security-reviewer v2.0 | ✅ 通過 | all fixes applied | atomic enroll (INSERT ON CONFLICT DO NOTHING), error handling |
| go test -race | ✅ 通過 | no data races | |

**Spaced Repetition 設計決策:**
- SM-2 pure function: no side effects, easy to test, handler computes next state then persists
- Atomic enroll: `INSERT ... ON CONFLICT DO NOTHING RETURNING *` → ErrConflict sentinel (no TOCTOU race)
- Domain types in `spaced.go`, store conversion in `store.go` (int ↔ int32)
- Schema in `001_initial.up.sql` (development stage, no migration versioning)

**Spaced Repetition 審查修復記錄:**
- security-reviewer: SubmitReview swallowed all errors as 404 → split errors.Is(ErrNotFound) from infra errors
- security-reviewer: Enroll check-then-act race → atomic InsertInterval with ON CONFLICT DO NOTHING
- go-reviewer: InsertParams/UpsertParams in store.go → moved to spaced.go (domain types file)

**API Endpoints:**
- `GET /api/admin/spaced/due?limit=50` — list notes due for review (default 50, max 100)
- `POST /api/admin/spaced/review` — submit review `{note_id, quality: 0-5}`
- `POST /api/admin/spaced/enroll` — enroll note `{note_id}`

### Content Maturity

| 項目 | 狀態 | 驗收 | 備註 |
|------|------|------|------|
| maturity score calculation | ⬜ 待開始 | | |
| maturity-based content promotion | ⬜ 待開始 | | |

---

## Phase 1.5: Source Decoupling

| 項目 | 狀態 | 驗收 | 備註 |
|------|------|------|------|
| Notion Source Registry | ✅ 完成 | build/vet/lint/test 0 issues + 3 reviewers | CRUD + toggle + sqlc + routes + reviewer fixes |
| Obsidian Tier 2 | ⬜ 待開始 | | 需要 data |
| Cloudflare Tunnel 設定 | ⬜ 待開始 | | 需要 infra |

---

## Phase 3: Intelligence Layer

| 項目 | 狀態 | 驗收 | 備註 |
|------|------|------|------|
| Unified weekly report | ⬜ 待開始 | | 需要 bidirectional writes |
| Drift Detection | ✅ 完成 | build/vet/lint/test 0 issues | GET /api/admin/stats/drift — activity vs goals by area |
| Session Reconstruction | ✅ 完成 | build/vet/lint/test 0 issues, 8 unit tests | 30min gap grouping, nested in activity package |
| Knowledge Graph (Wikilinks) | ✅ 完成 | build/vet/lint/test 0 issues, 11 parser tests | ParseWikilinks + note_links table + B1 sync integration |
| Monthly Flows | ⬜ 待開始 | | 需要 bidirectional writes |

---

### Admin Stats API

| 項目 | 狀態 | 驗收 | 備註 |
|------|------|------|------|
| internal/stats/ package | ✅ 完成 | build/vet/lint 0 issues | 11 data sources, cross-table aggregation |
| GET /api/admin/stats | ✅ 完成 | replaces hardcoded stub | nested response (contents, collected, feeds, flow_runs, projects, reviews, notes, activity, spaced, sources, tags) |

---

## Phase 4: Public & Portfolio

| 項目 | 狀態 | 驗收 | 備註 |
|------|------|------|------|
| Learning Dashboard | ✅ 完成 | build/vet/lint/test 0 issues | GET /api/admin/stats/learning — spaced + notes + activity + tags |
| Personal Changelog | ✅ 完成 | build/vet/lint 0 issues | GET /api/admin/activity/changelog admin-only, grouped by date |

---

## Tier Classification (from comprehend agent)

| Tier | 項目 | 可執行條件 |
|------|------|-----------|
| 0 | MCP Server | ✅ 完成 |
| 1 | ~~Genkit P2 split~~, ~~Notion Source Registry~~, ~~Spaced Repetition~~, Content Maturity (blocked: needs signals), ~~Token usage logging (SKIPPED)~~ | 現在可做 |
| 2 | Obsidian Tier 2, Knowledge Graph, Drift Detection, Session Reconstruction | 需要 data |
| 3 | Cloudflare Tunnel, 各前端 UI | 需要 infra |
| 4 | Unified weekly report, Monthly flows | 需要 bidirectional writes |
| 5 | Cross-Project Transfer, Retrospective Intelligence | 長期目標 |

---

## User Work Items (Koopa 負責)

| 項目 | 狀態 | 備註 |
|------|------|------|
| E1: Tag management frontend | 🔄 進行中 | Angular, 兩個 tab (Canonical Tags + Tag Aliases) |
| F1-F6: VPS 部署相關 | ⬜ 待開始 | 批次處理 |
| Stage 3: VPS 驗證 B1/B3 | ⬜ 待開始 | scripts/verify_stage3.sql 已準備 |
