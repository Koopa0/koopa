# koopa0.dev — 決策紀錄

## Decision Framework

### Tier 分級

與 go-spec 的開發 lifecycle tier 對齊：

| Tier | 範圍 | 決策紀錄方式 |
|------|------|-------------|
| **Tier 1** | 小改動（bug fix, typo, 1-3 files） | Commit message 足夠 |
| **Tier 2** | 中型 feature（existing package, no new types） | 一行 decision + rationale in commit body 或 build log |
| **Tier 3** | 架構改動（new package, design decisions） | 完整 Decision Record（見下方格式） |

### Decision Record 格式

```markdown
## [YYYY-MM-DD] Decision Title

**Context**: 我們面對什麼問題？
**Options Considered**: 考慮了哪些方案？
**Decision**: 選了什麼？
**Rationale**: 為什麼選這個？
**Consequences**: 這個決策的影響是什麼？
**Status**: Active / Superseded by [link]
```

---

## Decision Index

以下決策從 codebase 的結構、git history、和 PLATFORM-VISION.md 中 reverse-engineer 出來。

### Foundation Decisions

#### [2026-02] Single Migration File Strategy

**Context**: 專案在開發初期，schema 頻繁變動。
**Options Considered**: (1) 每次 schema 變更新增 migration 檔 (2) 開發階段只維護一個 001_initial.up.sql
**Decision**: 開發階段直接修改 001_initial.up.sql，不建新 migration 檔。
**Rationale**: 開發階段 schema 不穩定，累積大量 migration 檔只增加認知負擔。Production deploy 前再凍結 001 並開始 002+。
**Consequences**: 開發環境需要 `DROP` + `CREATE` 重建 DB。不適用於已有 production data 的環境。
**Status**: Active（dev 階段）

#### [2026-02] Package-by-Feature, Not by Layer

**Context**: Go 後端的 package 組織方式。
**Options Considered**: (1) DDD layers（domain/application/infrastructure） (2) Layer-based（handlers/, services/, repositories/） (3) Package-by-feature（internal/task/, internal/content/）
**Decision**: Package-by-feature。
**Rationale**: Go idiom — packages reflect what the code does, not what pattern it follows. DDD layers 在 Go 裡增加不必要的 indirection。Google Go Style Guide 也建議避免 generic package names。
**Consequences**: 每個 feature package 自包含 types + handler + store + tests。Cross-feature 依賴透過 consumer-defined interfaces。PreToolUse hook 強制阻擋 services/ 等目錄。
**Status**: Active

#### [2026-02] sqlc over ORM

**Context**: 選擇資料庫存取方式。
**Options Considered**: (1) GORM (2) sqlx (3) sqlc (4) raw pgx
**Decision**: sqlc + pgx/v5。
**Rationale**: SQL-first approach — 寫真正的 SQL，生成 type-safe Go code。不隱藏 SQL semantics（不像 ORM），但比 raw pgx 更 type-safe。與 PostgreSQL 特定功能（pgvector, JSONB, array）整合最好。
**Consequences**: 每個 feature 需要 query.sql 檔案。Generated code 在 internal/db/（NEVER edit）。需要跑 `make sqlc` 重新生成。
**Status**: Active

#### [2026-02] Standard Library HTTP (No Framework)

**Context**: 選擇 HTTP server framework。
**Options Considered**: (1) chi (2) gin (3) echo (4) net/http (Go 1.22+)
**Decision**: 純 net/http，使用 Go 1.22+ 的 method routing。
**Rationale**: Go 1.22 加入了 `"GET /api/contents/{slug}"` 語法，消除了 chi/gorilla 的主要優勢。零依賴、零 learning curve、零 framework lock-in。
**Consequences**: Middleware 是 `func(http.Handler) http.Handler` 標準簽名。Path params 用 `r.PathValue("slug")`。不需要 third-party routing。
**Status**: Active

### Data Architecture Decisions

#### [2026-03] Notion as Task/Goal/Project Source of Truth

**Context**: Task 管理需要一個 source of truth。
**Options Considered**: (1) 純 PostgreSQL（本地優先） (2) 純 Notion（Notion 優先） (3) 混合式（Notion 是 source of truth，本地有擴充欄位）
**Decision**: 混合式。Notion 是 source of truth for core fields（title, status, due date），PostgreSQL 擴充 local-only fields（my_day, energy, priority）。
**Rationale**: Koopa 已有 Notion workflow。強迫遷移會增加摩擦。但 Notion API 不提供 my_day 等概念，需要本地擴充。
**Consequences**: 需要同步機制（Notion webhook → local upsert）。寫回也需要雙向（complete_task 更新 local + Notion）。Notion sync 失敗不應阻塞 local operation。
**Status**: Active

#### [2026-03] pgvector for Semantic Search (Not External Vector DB)

**Context**: Knowledge notes 需要 semantic search capability。
**Options Considered**: (1) Pinecone (2) Weaviate (3) pgvector in PostgreSQL
**Decision**: pgvector in PostgreSQL。
**Rationale**: 一個 DB 覆蓋 relational + full-text + vector search。規模是個人知識庫（數千筆），不需要分散式向量 DB 的 scale。同一個 transaction 可以 join vector results 和 relational data。
**Consequences**: 768-dim embeddings（Gemini）。HNSW index（m=16, ef=64）。Embedding generation 依賴 Gemini API。
**Status**: Active

#### [2026-03] Session Notes as Cross-Environment Context Bridge

**Context**: Claude（MCP）和 Claude Code（local）需要共享上下文（today's plan, reflection, metrics, insights）。
**Options Considered**: (1) 用 file system（.md files） (2) 用 database table
**Decision**: `session_notes` table，用 `note_type` 區分（plan/reflection/context/metrics/insight），用 `source` 區分來源（claude/claude-code/manual）。
**Rationale**: File-based 無法跨 environment 共享。Database table 讓 MCP 和 HTTP API 都能讀寫。JSONB metadata 支援不同 note_type 的結構化資料。
**Consequences**: 是 Plan → Execute → Reflect 閉環的 spine。Morning context 聚合 session_notes + tasks + goals + activity 提供完整上下文。
**Status**: Active

#### [2026-03] Insight Layer（Hypothesis Lifecycle）

**Context**: 觀察到 patterns 和 trends 需要被追蹤和驗證，而不是寫在 session note 裡就忘了。
**Options Considered**: (1) 獨立的 insights table (2) session_notes 加 type=insight + metadata
**Decision**: 用 session_notes(type=insight) + metadata JSON（hypothesis, status, evidence）。
**Rationale**: 不需要獨立 table——insight 本質上是一種 session note，只是 lifecycle 不同（unverified → verified/invalidated → archived）。用 metadata JSONB 存結構化資料。
**Consequences**: Insight 有 14 天 auto-archive policy（verified/invalidated 後 14 天自動 archive）。`get_active_insights` 和 `update_insight` 是 MCP tools。
**Status**: Active

### AI Pipeline Decisions

#### [2026-02] Genkit for AI Flow Orchestration

**Context**: 需要一個 framework 來管理多步驟 AI pipeline。
**Options Considered**: (1) Raw API calls (2) LangChain Go (3) Firebase Genkit
**Decision**: Firebase Genkit。
**Rationale**: 原生 Go SDK（不是 Python-first 的 port）。Flow abstraction 適合多步驟 pipeline。支援 Gemini + Claude（multi-model）。Prompt template management 內建。
**Consequences**: 18 specialized flows in internal/flow/。每個 flow 有獨立的 input/output types。flowrun.Runner 統一管理 execution + retry + alerting。
**Status**: Active

#### [2026-03] Dual Model Strategy（Gemini + Claude）

**Context**: 不同 AI 任務有不同的 model 需求。
**Decision**: Gemini 用於 embeddings 和 content review/tagging。Claude 用於 content polish 和 generation。
**Rationale**: Gemini 的 embedding model 性價比高。Claude 的寫作品質更適合 polish 和 generation。不綁定單一 model provider。
**Consequences**: 兩套 API key（GEMINI_API_KEY, CLAUDE_MODEL）。MockMode flag 允許開發時不實際呼叫 AI。
**Status**: Active

### Frontend Decisions

#### [2026-02] Topic-Driven Architecture（Not Format-Driven）

**Context**: 前端內容組織方式。
**Options Considered**: (1) 按格式分（/articles, /til, /notes） (2) 按主題分（/topics/backend-engineering） (3) 兩者並存
**Decision**: 兩者並存，但主題優先。
**Rationale**: 訪客按興趣瀏覽（"我想看 backend engineering 的內容"），不關心是 article 還是 TIL。格式路由保留作為 secondary navigation。
**Consequences**: Topic model + 主題頁面。Mixed feed 混合所有格式。Content-topic 是 M:M 關係。
**Status**: Active

#### [2026-02] SSR for SEO

**Context**: Angular 預設是 CSR，對 SEO 不友好。
**Decision**: 使用 Angular SSR（built-in since Angular 17+）。
**Rationale**: 個人品牌網站需要 SEO。SSR 讓 search engines 能正確 index 內容。不需要額外的 pre-rendering service。
**Consequences**: BFF proxy at `/bff/*` → backend at `http://backend:8080`。需要注意 browser-only APIs（localStorage 等）在 SSR 環境不可用。
**Status**: Active

### Infrastructure Decisions

#### [2026-02] MCP as First-Class Interface

**Context**: 需要讓 Claude 能直接操作知識引擎。
**Options Considered**: (1) 只用 HTTP API + curl (2) Custom Claude tool definitions (3) MCP server
**Decision**: MCP server（`cmd/mcp/`）。
**Rationale**: MCP 是 Anthropic 的標準 tool protocol。支援 stdio（local Claude Code）和 HTTP（remote Claude.ai）。Tool schema 自動 discovery。不需要手動維護 tool definitions。
**Consequences**: 獨立 binary（cmd/mcp/）。兩種 transport（stdio, HTTP + OAuth）。30+ tools（14 read, 7+ write）。是 Claude daily workflow 的 primary interface。
**Status**: Active

#### [2026-03] Docker + VPS（Not Serverless）

**Context**: 部署策略。
**Decision**: Docker containers on VPS。
**Rationale**: 單一 binary 部署簡單。需要 persistent connection 到 PostgreSQL。Cron jobs 和 webhook 處理需要 long-running process。Serverless 的 cold start 不適合 webhook handler。
**Consequences**: Dockerfile multi-stage build。Docker Compose for dev。Cloudflare Tunnel for ingress。
**Status**: Active
