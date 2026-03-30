# 後端程式碼審查彙整報告

> **日期**: 2026-03-30
> **審查來源**: Auggie Code Review、Claude Code Session 1、Claude Code Session 2
> **範圍**: `internal/` 全部 31 個 package
> **基於**: 2026-03-29 審計後的 codebase 狀態

---

## 整體評價

三份報告一致認為：**這是一個組織良好、符合 Go 慣例的 codebase**。Package-by-feature 結構正確應用，interface 紀律強（從 82 降到 10，全部有多實作或 cycle 防護理由），error handling 模式大致一致，concurrency 模式正確。

問題集中在 **refinement 層面**，不是架構性錯誤。

---

## 問題清單（按優先級排序）

### P0 — 會導致 production bug 的問題

| # | 問題 | 位置 | 說明 | 修復難度 |
|---|------|------|------|----------|
| 1 | **task 缺少 ErrNotFound sentinel** | `task/task.go` | task 是唯一沒有定義 ErrNotFound 的 feature package。Handler 把所有 store error 當 404 回傳 — DB connection failure 也變成 "task not found"。 | 小 |
| 2 | **goal store 未 map pgx.ErrNoRows** | `goal/store.go:93,102,112` | GoalByTitle、UpdateStatus、IDByNotionPageID 沒有檢查 pgx.ErrNoRows，raw pgx error 直接傳到 handler，回 500 而非 404。 | 小 |
| 3 | **review Edit handler 語意錯誤** | `review/handler.go:81-103` | Edit handler 名為「編輯」但實際忽略 request body、直接 call ApproveReview。語意完全錯誤。 | 小 |
| 4 | **task handler 吞錯誤** | `task/handler.go:152,282` | Upsert error 被吞掉（回 201 但 DB 寫入失敗）；api.Decode error 被 silently ignore。 | 小 |
| 5 | **review Reject 未驗證 notes** | `review/handler.go:56-78` | 退回審核時 notes 可以是空字串，應該回 400。 | 小 |

### P1 — 資料正確性 / 一致性問題

| # | 問題 | 位置 | 說明 | 修復難度 |
|---|------|------|------|----------|
| 6 | **15 個 package 的 ErrNotFound 訊息完全相同** | 全 codebase | 全部都是 `errors.New("not found")`。當 error chain 跨 package 組合時，`errors.Is` 匹配會混淆，debug 輸出無法分辨來源。 | 小 |
| 7 | **Create/Update 驗證不一致** | content、tag、topic、task、project | Create handler 驗證 type/name/title 等欄位，但 Update handler 不檢查 pointer-optional 欄位是否為空字串。`*string` 指向 `""` 會通過 Update。 | 小 |
| 8 | **feed/entry handler ErrNotFound 回 500** | `feed/entry/handler.go:50-88` | Curate/Ignore handler 沒有 map ErrNotFound，所有 error 都回 500。 | 小 |
| 9 | **project Delete 不偵測 missing row** | `project/handler.go:115` | Delete 沒 map ErrNotFound，store 也沒偵測 missing rows。 | 小 |

### P2 — 依賴方向 / 結構性問題

| # | 問題 | 來源共識 | 說明 | 修復難度 |
|---|------|----------|------|----------|
| 10 | **github → activity 反向依賴** | 3/3 報告一致 | `github.Client.Compare()` 回傳 `*activity.DiffStats`。Infrastructure package 不該 import feature package 的 type。應在 github 定義 DiffStats，由 caller 轉換。 | 小 |
| 11 | **task → ai 依賴** | 2/3 報告一致 | `task/store.go` import `ai` 取得 `ai.PendingTask` / `ai.ProjectCompletion` DTO。Domain package 不該依賴 AI package。應把這些 type 移到 task。 | 小 |
| 12 | **topic → content 直接 coupling** | 2/3 報告一致 | `topic/handler.go` 直接依賴 `*content.Store`，違反 consumer-side interface 原則。應定義 `ContentByTopicReader` interface。 | 小 |
| 13 | **project → tag.Slugify 工具性依賴** | 1/3 報告指出 | `project/notion.go` import `tag` 只為了用 `tag.Slugify`，把 tag 變成 string utility。應把 slug normalization 搬到 project 或共用 `internal/slug`。 | 小 |

### P3 — God Package / 職責過大

| # | 問題 | 來源共識 | 現況 | 建議 |
|---|------|----------|------|------|
| 14 | **mcp 是 God Package** | 3/3 報告一致 | 31 檔、721 行 server.go、20+ 欄位、14 internal imports、239 exports。包含 OAuth、O'Reilly client、全部 tool handler。 | 短期：提取 oauth.go → `internal/mcpauth`、oreilly.go → `internal/oreilly`。長期：按 bounded context 分 sub-package。 |
| 15 | **ai package 過大** | 2/3 報告一致 | 15 檔、8+ 個 flow、shared utility + 放錯位置的 type（mock.go 含 production type）。 | 移 PendingTask/ProjectCompletion 到 task。重命名 mock.go → types.go。考慮 flow 拆子包。 |
| 16 | **content handler 職責過廣** | 2/3 報告一致 | 708 行，同時負責 CRUD、RSS 生成、Sitemap 生成、knowledge graph 計算。 | 提取 RSS/Sitemap 到獨立檔案或 package。Knowledge graph builder 至少拆成獨立檔案。 |
| 17 | **notion handler 職責過廣** | 2/3 報告一致 | 514 行，混合 webhook auth、dedup、source routing、property extraction、cross-entity upsert、event emission。 | 按 entity 拆 sync 到獨立檔案。Handler 只做 protocol I/O。 |
| 18 | **pipeline 混合太多關注點** | 2/3 報告一致 | sync、webhook routing、manual trigger API 全在一個 package。已有 sub-struct 但仍是一個 package。 | 等有新功能需求時再拆成 `pipeline/contentsync`、`pipeline/webhook`、`pipeline/triggers`。 |

### P4 — Constructor 參數過多

| # | 函式 | 參數數 | 建議 |
|---|------|--------|------|
| 19 | `ai/report.NewWeekly` | 14 | 引入 Deps struct |
| 20 | `ai.NewContentReview` | 11 | 引入 Deps struct |
| 21 | `mcp.NewServer` | 11 | 引入 Deps struct |
| 22 | `ai.Setup` | 9 | 把 gh/notifier/tokenBudget/loc/logger 打包成 PipelineDeps |
| 23 | `ai.NewContentStrategy` | 9 | 引入 Deps struct |
| 24 | `ai.NewBuildLog` | 9 | 引入 Deps struct |
| 25 | `ai.NewProjectTrack` | 8 | 引入 Deps struct |
| 26 | `content/store.rowToContent` | 21 | 改為接收 sqlc row struct |

### P5 — 命名 / 風格

| # | 問題 | 位置 | 說明 |
|---|------|------|------|
| 27 | **Type stutter** | content.Content、budget.Budget、goal.Goal 等 | 多個核心 package type name = package name。是 deliberate convention 但違反 Effective Go。設計決策，非 bug。 |
| 28 | **mcp unexported method Get prefix** | `mcp/search.go:973`、`mcp/insights.go:46` | `getSessionNotes`、`getActiveInsights` 應改為 `sessionNotes`、`activeInsights`。 |
| 29 | **github receiver name** | `github/github.go` 全 Client method | 用 `g` 而非慣例的 `c`。Minor。 |
| 30 | **monitor store stutter** | `monitor/store.go:25` | Store methods 用 "TrackingTopic" prefix，造成 stutter。 |
| 31 | **ai/mock.go 命名錯誤** | `ai/mock.go` | 含 production type（PendingTask、ProjectCompletion），檔名暗示是 test mock。應改名 types.go。 |

### P6 — 其他（低風險 / 已知可接受）

| # | 問題 | 位置 | 說明 | 處理 |
|---|------|------|------|------|
| 32 | auth panic on crypto/rand failure | `auth/handler.go:238` | 2/3 報告認為可接受（stdlib 也這樣做），1/3 建議改 return error。 | 保留或改，都合理 |
| 33 | X-Forwarded-For spoofable in rate limiter | `server/middleware.go:220` | 單人 VPS 環境風險低，但 production 需 trusted proxy 設定。 | 加 trusted proxy 設定 when scaling |
| 34 | reconcile 兩個 goroutine 都失敗時回「all consistent」 | `reconcile/reconcile.go:97` | Edge case — WaitGroup error handling 不完整。 | 中等 |
| 35 | webhook.Stop double-call panic | `webhook/replay.go:46` | close(channel) 二次 call 會 panic。加 sync.Once。 | 小 |
| 36 | testdb TRUNCATE string concat | `testdb/testdb.go:73,153` | test-only code，table name 來自 constant。可接受但建議加 comment。 | 無需處理 |
| 37 | upload.NewS3Client 接收未使用的 ctx | `upload/client.go:12` | 移除或用於 AWS config loading。 | 小 |
| 38 | api.Response 用 `any` type | `api/api.go:13` | 建議改 generics `Response[T]`。低優先。 | 等 Go generics 成熟再改 |
| 39 | MCP cognitive complexity (gocognit) | `mcp/search.go`、`mcp/content.go` 等 | 已在 post-audit backlog。 | 觸碰時再改 |

---

## 三份報告共識 vs 分歧

### 全部一致（高信心）

1. github → activity 反向依賴（3/3 CRITICAL/HIGH）
2. mcp 是 God Package（3/3 CRITICAL/NEEDS WORK）
3. ErrNotFound 訊息重複（3/3 HIGH/MEDIUM）
4. Constructor 參數過多（3/3 MEDIUM/HIGH）
5. content handler 職責過廣（3/3 MEDIUM/HIGH）

### 兩份一致

6. ai package 過大（Claude Code 1 + 2）
7. task → ai 反向依賴（Claude Code 1 + 2）
8. task 缺少 ErrNotFound（Claude Code 1 + 2）
9. notion handler 過廣（Auggie + Claude Code 2）
10. Create/Update 驗證不一致（Claude Code 1 + 2）

### 分歧

| 主題 | Auggie | Claude Code 1 | Claude Code 2 |
|------|--------|---------------|---------------|
| 整體評價 | STRONG | ACCEPTABLE | NEEDS WORK |
| ai.Flow interface 位置 | CRITICAL → 自己改判 PASS | PASS | PARTIAL |
| notify.Notifier interface | MEDIUM → PASS | PASS | PASS |
| feed.Store 含 notification | 未提及 | 未提及 | HIGH（職責混合） |
| pipeline 拆分 | 未提及 | MEDIUM（設計） | FAIL（職責） |
| auth panic | LOW（可接受） | MEDIUM（panic） | HIGH（改 return error） |

---

## 建議執行順序

### 第一波：P0 bug fixes（1-2 天）

1. task: 加 ErrNotFound sentinel + 修 handler error mapping + 修吞 error
2. goal: store 加 pgx.ErrNoRows 檢查
3. review: 修 Edit handler 語意 + Reject 加 notes 驗證
4. feed/entry: handler 加 ErrNotFound mapping
5. project: Delete 加 ErrNotFound mapping

### 第二波：P1 一致性修復（1-2 天）

6. 15 個 ErrNotFound 加 package prefix
7. 5 個 package 的 Update handler 加 optional field 驗證

### 第三波：P2 依賴方向修正（1 天）

8. github: DiffStats 移到 github package
9. task: PendingTask/ProjectCompletion 移到 task + ai/mock.go rename
10. topic: 定義 consumer-side interface

### 第四波：P4 constructor refactor（2-3 天）

11. ai/ 全部 constructor 改 Deps struct
12. mcp.NewServer 改 Deps struct
13. content/store.rowToContent 改 struct

### 第五波：P3 結構重組（按需）

14. mcp 提取 oauth + oreilly
15. content handler 拆 RSS/Sitemap/graph
16. 其餘等觸碰時再改

---

## 與現有 backlog 的關係

| 現有 backlog 項目 | 本報告對應 |
|-------------------|-----------|
| MCP cognitive complexity (post-audit) | P3 #14 + P6 #39 |
| Test coverage for task/feed/entry (DA plan) | 第一波修完 bug 後再補測試 |
| Codex REDESIGN suggestions (post-audit) | P3 全部 |
| 14+ packages zero tests (DA plan) | 不在本報告範圍，但修 P0 後應優先補 |
