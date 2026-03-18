# Genkit AI Pipeline Audit Report — koopa0.dev

> **審查日期**: 2026-03-13
> **審查範圍**: `blog/backend/internal/flow/` 全部 9 個 Genkit flow、prompt 工程、tool 設計、flow runner 架構
> **交叉比對**: `resonance/backend/` 的 Genkit 實作（對話式 AI 文學共創平台）
> **目的**: 提交給 Claude 和 Gemini 進行雙方交叉嚴格審查

---

## Executive Summary

koopa0.dev 的 Genkit pipeline 是一個 **功能完整、架構穩健的 AI 內容處理系統**，具備 9 個 flow、token budget、persistent job queue、retry mechanism。但與 resonance 的 AI 工程相比，存在以下可改進的面向：

| 面向 | Blog (koopa0.dev) | Resonance | 差距等級 |
|------|-------------------|-----------|----------|
| Prompt 工程深度 | 基礎指令式 | 深層行為規範式 | **HIGH** |
| Tool 整合 | **零 Tool** | Web Search Tool | **HIGH** |
| 結構化輸出可靠性 | 直接信任 LLM JSON | Multi-stage fallback parser | **MEDIUM** |
| Flow 語意粒度 | 粗粒度（1 flow 多步驟） | 細粒度（可獨立呼叫+組合） | **MEDIUM** |
| Prompt 版本管理 | `//go:embed` 嵌入 | 同樣嵌入，但有 template injection | **LOW** |
| 評估框架 | 無 | LLM-as-Judge 4 維度加權評分 | **HIGH** |
| Moderation | 無 | 完整 moderation flow + care context | **N/A**（場景不同） |
| Mock 模式 | 有 | 有 | **EQUAL** |

---

## Part 1: Flow 設計審查

### 1.1 Flow 清單與分類

| Flow | 類型 | Model | 觸發方式 | 評價 |
|------|------|-------|----------|------|
| `content-review` | 內容處理 | Gemini | Event (content created) | ✅ 設計良好：1 sequential + 4 parallel |
| `content-polish` | 內容增強 | Claude | Manual (admin API) | ✅ 正確選擇 Claude 做文風潤色 |
| `bookmark-generate` | 內容生成 | Gemini | Event (collected item) | ⚠️ 缺少 source URL 驗證 |
| `build-log-generate` | 內容生成 | Gemini | Manual/Cron | ⚠️ 輸出要 JSON 但 prompt 不明確 |
| `digest-generate` | 摘要合成 | Gemini | Manual | ✅ 結構清晰 |
| `morning-brief` | 通知 | Gemini | Cron 07:30 | ✅ Graceful degradation |
| `weekly-review` | 通知 | Gemini | Cron Mon 09:00 | ✅ 5 source parallel fetch |
| `project-track` | 追蹤 | Gemini | Webhook (GitHub push) | ✅ 設計合理 |
| `content-strategy` | 分析 | Gemini | Cron Mon 03:00 | ⚠️ Gap analysis 邏輯在 Go 層，不在 prompt |

### 1.2 架構問題

#### [CRITICAL] 無 Genkit Tool 整合

Blog 的 9 個 flow 全部使用 `genkit.Generate()` 或 `genkit.GenerateData[T]()`，**沒有任何一個使用 `genkit.DefineTool()`**。

**問題**：
- `bookmark-generate` 接收 RSS 收集的文章 metadata，但不驗證文章是否仍然存在、URL 是否可訪問
- `content-review` 的 tag 分類依賴 prompt 指示「只從提供的列表中選擇」，但 LLM 有時會幻覺出不存在的 tag
- `build-log-generate` 從 GitHub 取得 commit list，但不驗證 commit 是否真實（已經由 Go 層保證，但如果要做更深的 commit 分析則需要 tool）

**Resonance 做法**：
- 定義了 `search.RegisterTool()` — Web Search Tool
- Dialogue flow 使用 `ai.WithTools(searchTool)` 讓 AI 在提及作品事實時**強制搜尋驗證**
- Prompt 中明確規定：「任何關於作品的事實性聲明都必須先搜尋確認」

**建議**：
1. 為 `bookmark-generate` 增加 URL 驗證 tool（檢查 URL 可訪問性 + 抓取最新標題）
2. 為 `content-review` 的 tag 分類增加 topic lookup tool（取代 prompt 中的 tag 列表注入）
3. 長期考慮：為 `content-strategy` 增加 trending topic search tool

#### [IMPORTANT] Flow 語意粒度過粗

`content-review` 是一個 **5 步驟的 mega-flow**：proofread → excerpt → tags → reading time → embedding。
這些步驟混在同一個 flow 中，無法獨立執行或重試單一步驟。

**Resonance 做法**：
- `understanding` 和 `weaver` 是獨立的 Genkit flow
- 組合進 `storyGeneration` top-level flow
- 每個 flow 可以獨立呼叫（用於 eval/dev UI）
- 失敗時可以只重試失敗的 flow，不需要從頭跑

**建議**：
考慮將 `content-review` 拆分為：
- `content-proofread`：校對
- `content-metadata`：excerpt + tags + reading time
- `content-embed`：embedding 生成

這樣可以：
- 獨立重試（embedding 失敗不需要重跑 proofread）
- 獨立評估（可以單獨衡量 proofread 品質）
- 漸進式處理（先快速生成 metadata，再慢慢跑 proofread）

#### [SUGGESTION] 缺少 Flow Composition 模式

Blog 的 flow registry 是平面的 `map[string]Flow`，所有 9 個 flow 都是獨立的。
沒有 flow-calls-flow 的組合模式。

**Resonance 做法**：
- `storyGeneration` flow 內部呼叫 `understanding` 和 `weaver` flow
- 支援 novel 的 two-phase pause（理解 → 角色確認 → 生成）

**建議**：
考慮 `content-review` + `content-polish` 的自動鏈：
- 如果 review level = "auto" 且 polish 啟用，自動觸發 polish
- 需要 flow composition，不是手動在 handler 層串接

---

## Part 2: Prompt 工程審查

### 2.1 Prompt 品質評分

| Prompt | 長度 | 結構 | 約束力 | 風格指導 | 輸出格式 | 評分 |
|--------|------|------|--------|----------|----------|------|
| review.txt | 短 | 基礎 | 中 | 無 | JSON spec | **C+** |
| excerpt.txt | 極短 | 極簡 | 弱 | 無 | 純文字 | **C** |
| tags.txt | 極短 | 極簡 | 中 | 無 | JSON array | **C** |
| polish.txt | 中 | 良好 | **強** | **優秀** | 明確 | **A-** |
| bookmark.txt | 中 | 良好 | 中 | 中 | JSON spec | **B** |
| build_log.txt | 中 | 良好 | 中 | 中 | JSON spec | **B** |
| digest.txt | 中 | 良好 | 中 | 中 | Markdown | **B** |
| morning_brief.txt | 中 | 良好 | 中 | 良好 | 純文字 | **B+** |
| weekly_review.txt | 中 | 良好 | 中 | 良好 | 純文字 | **B+** |
| content_strategy.txt | 短 | 基礎 | 弱 | 弱 | 純文字 | **C+** |
| project_track.txt | 短 | 基礎 | 中 | 弱 | 純文字 | **C+** |

**整體評分：B-**

### 2.2 Prompt 深度比較

#### Blog: 指令式 Prompt（Tell what to do）

```
# review.txt 風格
你是 content reviewer。
Review for: grammar, spelling, clarity, accuracy。
Output: JSON {level, notes, corrections}。
```

特點：
- 告訴 AI 要「做什麼」
- 不告訴 AI「不要做什麼」
- 不定義邊界情況
- 不提供 few-shot examples

#### Resonance: 行為規範式 Prompt（Define how to be）

```
# system.txt 風格
## 你是什麼
伴隨者，不是提取者。共同發現，不是引導答案。

## 你可以做什麼
- 分享作品特質
- 表達自己的感受
- 提及創作者意圖

## 你不能做什麼
- 預設用戶情感
- 引用原文
- 說教

## should_confirm 邏輯
必須滿足：情感方向 + 至少一輪 hook 回應
個人素材定義：具體記憶、事件、人名/描述、場所/情境
非素材：「好聽」「有氣氛」、不帶事件的時間點

## 連續短回覆規則
短回覆（<10 字 或 無個人素材）→ 下一輪必須包含 2-3 具體方向提示
```

特點：
- 定義 AI 的**身份和立場**
- 明確列出**可以做**和**不能做**
- 定義**邊界情況**的處理邏輯
- 提供**行為觸發條件**

### 2.3 具體改進建議

#### [CRITICAL] review.txt — 缺少審查標準定義

**現狀**：
```
Review for: grammar, spelling, clarity, technical accuracy.
Assign level: auto|light|standard|strict.
```

**問題**：
- 什麼程度的問題算 "auto" vs "light"？
- 技術文章的「clarity」標準和個人散文不同
- 沒有 few-shot example 示範每個 level 的判斷

**建議改進**：
```
## Level 判斷標準

### auto（可直接發布）
- 無語法錯誤
- 技術術語使用正確
- 段落邏輯清晰
- 示例：文章只有 1-2 處標點符號問題

### light（輕微修正）
- 2-5 處語法/用字問題
- 結構可以但不影響理解
- 示例：有幾處贅字或不自然的連接詞

### standard（需要審查）
- 技術描述有歧義
- 段落邏輯跳躍
- 超過 5 處語法問題
- 示例：概念解釋不完整，讀者可能誤解

### strict（需要仔細編輯）
- 技術錯誤
- 邏輯矛盾
- 大量語法問題
- 示例：API 用法描述與實際行為不符
```

#### [CRITICAL] excerpt.txt — 過於簡略

**現狀**：
```
Generate a concise excerpt. 2-3 sentences, max 200 characters.
```

**問題**：
- 沒有指定 excerpt 應該吸引讀者還是總結內容
- 沒有區分不同 content type 的 excerpt 策略
- 200 characters 對中文可能太短（約 66 個中文字）

**建議改進**：
```
生成內容摘要（excerpt），用於文章列表頁和 SEO meta description。

## 目的
讓讀者在 3 秒內決定是否點進文章。不是「總結」，是「吸引」。

## 規則
- 2-3 句，最多 160 字（SEO 最佳長度）
- 第一句：這篇文章解決什麼問題或探討什麼主題
- 第二句：用什麼方法或從什麼角度
- 可選第三句：讀者會學到什麼
- 不要用「本文將介紹」「這篇文章討論」等開頭
- 保留技術術語原文

## 按類型調整
- article/note：聚焦技術問題和解法
- essay：聚焦觀點和反思角度
- build-log：聚焦做了什麼和為什麼
- til：聚焦學到了什麼
- bookmark：聚焦為什麼值得讀
```

#### [IMPORTANT] tags.txt — 缺少分類策略

**現狀**：
```
Select from existing tags. 1-5 tags. JSON array.
```

**問題**：
- 沒有說明選 tag 的優先順序
- 沒有區分「主要 tag」和「次要 tag」
- 沒有處理邊界情況（文章跨多個領域）

**建議改進**：
```
從提供的 tag 列表中選擇最相關的 1-5 個 tag。

## 選擇策略
1. 首選：文章的核心技術或主題（最多 2 個）
2. 次選：文章涉及的工具或框架（最多 2 個）
3. 補充：文章的類別或領域（最多 1 個）

## 規則
- 只從提供的列表選擇，絕對不要發明新 tag
- 如果沒有完全匹配的 tag，選擇最接近的
- 寧可少選不要多選——3 個精準 tag 好過 5 個泛泛 tag
- 如果文章主要是個人反思且無技術內容，可以只選 1 個

## 不要選的情況
- tag 只在文章中被順帶提到，不是文章的焦點
- tag 太泛（如果有 "go" 和 "go-concurrency"，選後者）
```

#### [IMPORTANT] build_log.txt — JSON 輸出格式不可靠

**現狀**：
Prompt 要求輸出 JSON `{title, body, tags}`，但使用 `genkit.Generate()`（非 `GenerateData[T]`）。
Go 層手動 `json.Unmarshal` 解析。

**問題**：
- LLM 有時會在 JSON 前加上解釋文字
- 沒有 fallback parser（不像 resonance 的 `parseJSONLoose`）
- 如果解析失敗，整個 flow 失敗

**Resonance 做法**：
```go
func parseJSONLoose(text string, v any) error {
    // 1. Direct JSON parse
    // 2. Extract from ```json ... ```
    // 3. Extract from ``` ... ```
    // 4. First { to last } substring
}
```

**建議**：
1. 改用 `genkit.GenerateData[BuildLogResult]()` 讓 Genkit 處理 JSON 解析
2. 或者實作類似 resonance 的 `parseJSONLoose` 作為 fallback
3. 至少加上 retry（目前 build-log flow 沒有 retry 邏輯）

#### [SUGGESTION] polish.txt — 已經是最佳實踐

`polish.txt` 是 blog 所有 prompt 中**品質最高**的：
- ✅ 定義了身份（繁體中文技術寫作編輯）
- ✅ 正面規則（風格原則、段落紀律、節奏）
- ✅ 負面規則（禁忌：八股連接詞、空洞修飾、AI 腔調）
- ✅ 保留不動清單（code blocks、inline code、frontmatter）
- ✅ 明確輸出要求

**這個 prompt 的品質應該成為其他 prompt 的標準。**

### 2.4 Prompt Engineering Anti-Patterns

#### Anti-Pattern 1: 缺少 Negative Examples

Blog 的大多數 prompt 只告訴 AI 要做什麼，不告訴不要做什麼。

| Prompt | Has DO | Has DON'T |
|--------|--------|-----------|
| review.txt | ✅ | ❌ |
| excerpt.txt | ✅ | ❌ |
| tags.txt | ✅ | ⚠️ 只有「不要發明新 tag」 |
| polish.txt | ✅ | ✅ **完整禁忌清單** |
| bookmark.txt | ✅ | ⚠️ 簡略 |
| morning_brief.txt | ✅ | ⚠️ |
| weekly_review.txt | ✅ | ⚠️ |

Resonance 的 `SHARED_BANS_BLOCK` 有 10 條明確禁令，每條都有具體例子。

#### Anti-Pattern 2: 缺少 Few-Shot Examples

Blog 的所有 prompt 都沒有 few-shot examples。

Resonance 的 prompt 雖然也沒有嚴格的 few-shot，但有：
- 格式範例（morning_brief 的 emoji 分段示範）
- 行為觸發條件（should_confirm 的精確定義）
- 邊界情況處理（低素材模式的判斷標準）

#### Anti-Pattern 3: Temperature 與輸出格式不匹配

| Flow | Temp | Output | 問題 |
|------|------|--------|------|
| build-log | 0.6 | JSON | ⚠️ 中等 temp + JSON = 格式不穩定風險 |
| bookmark | 0.5 | JSON | ⚠️ 同上 |
| tags | 0.2 | JSON array | ✅ 低 temp + JSON = 穩定 |
| proofread | 0.3 | JSON | ✅ 低 temp + JSON = 穩定 |

**建議**：需要 JSON 輸出的 flow，temperature 不應超過 0.3。
或者使用 `GenerateData[T]()` 讓 Genkit 處理格式約束。

---

## Part 3: Tool 設計審查

### 3.1 現狀：零 Tool

Blog backend **完全沒有使用 Genkit Tool**。所有外部資料都由 Go 層預先查詢，再注入到 prompt 中。

### 3.2 Tool 使用時機分析

| 場景 | 現狀 | 應否用 Tool | 理由 |
|------|------|-------------|------|
| Tag 分類 | Go 查 DB → 注入 prompt | **可選** | Tag 列表小且固定，注入 prompt 可接受 |
| Bookmark URL 驗證 | 不驗證 | **建議** | RSS metadata 可能過時，URL 可能失效 |
| Content strategy 趨勢分析 | Go 計算 tag 分佈 → 注入 prompt | **建議** | AI 可以自己搜尋當前技術趨勢 |
| Build-log commit 分析 | Go fetch commits → 注入 prompt | **可接受** | commit 資料已由 Go 層可靠取得 |
| Proofread 參考查詢 | 不查詢 | **長期考慮** | 技術文章的 proofread 可以查官方文檔確認術語 |

### 3.3 與 Resonance 的 Tool 比較

**Resonance 的 Web Search Tool**：
```go
search.RegisterTool(g, searxngURL)
// Tool: 接收 query string → 回傳搜尋結果
// Dialogue flow 使用 ai.WithTools(searchTool)
// Prompt 規定：「任何事實性聲明必須先搜尋確認」
```

**關鍵差異**：
- Resonance 讓 **AI 決定何時搜尋**（tool calling）
- Blog 讓 **Go 層決定查什麼**（pre-fetch + inject）
- 兩者都是合理的設計，但 blog 的場景中有些適合 tool calling

### 3.4 建議的 Tool 設計

```go
// Tool 1: URL 健康檢查（for bookmark-generate）
genkit.DefineTool(g, "check-url", "檢查 URL 是否可訪問並取得最新標題",
    func(ctx context.Context, input struct{ URL string }) (struct{ Accessible bool; Title string }, error) {
        // HEAD request + title extraction
    },
)

// Tool 2: Topic 搜尋（for content-strategy）
genkit.DefineTool(g, "search-trending", "搜尋特定技術主題的近期趨勢",
    func(ctx context.Context, input struct{ Query string }) ([]SearchResult, error) {
        // 使用 SearxNG 或其他搜尋引擎
    },
)
```

---

## Part 4: Flow Runner 與基礎設施審查

### 4.1 Runner 架構 — ✅ 設計良好

| 面向 | 實作 | 評價 |
|------|------|------|
| Job 持久化 | PostgreSQL `flow_runs` 表 | ✅ Job 不會丟失 |
| Worker pool | Semaphore (chan struct{}, size 3) | ✅ 有界並發 |
| Dedup | DB query `PendingRunExists` | ✅ 防重複提交 |
| Retry | Cron 每 2 分鐘掃描 | ✅ 自動恢復 |
| Alert | LINE/Telegram 通知 | ✅ 失敗可觀測 |
| Graceful shutdown | Semaphore timeout + WaitGroup | ✅ 不會截斷進行中的 flow |
| Mock mode | 全部 9 flow 可 mock | ✅ 開發友善 |

### 4.2 Token Budget — ✅ 設計合理但有改進空間

**現狀**：
- 靜態估算（bookmark=2K, digest=5K 等）
- `atomic.CompareAndSwap` 無鎖預留
- Midnight reset

**問題**：
- 估算值是固定的，不反映實際 token 使用量
- 沒有追蹤實際消耗（Genkit 的 `resp.Usage()` 未被讀取）
- Budget 只是粗略保護，不是精確計量

**建議**：
1. 讀取 `resp.Usage().OutputTokens` + `resp.Usage().InputTokens` 更新實際使用量
2. 用實際消耗校準估算值（可以是 log 層面的，不需要改 budget 邏輯）

### 4.3 與 Resonance 的 Runner 比較

| 面向 | Blog | Resonance |
|------|------|-----------|
| Job 持久化 | ✅ PostgreSQL | ✅ PostgreSQL |
| 並發模型 | Semaphore + channel | WaitGroup + background goroutine |
| Retry | Cron-based scan | Per-flow retry (1-2次) |
| Dedup | DB-level check | N/A（每次生成都是唯一的） |
| Alert | LINE/Telegram | N/A（錯誤存 DB，前端輪詢） |
| Content policy | 不處理 | 不 retry（正確做法） |

**Blog 的 runner 在 retry 上有一個問題**：content policy block 也會被 retry。
Resonance 明確區分 transient failure（retry）和 content policy block（不 retry）。

**建議**：在 flow execution 時檢查 Genkit 的 `FinishReason`，如果是 content policy block，標記為 permanent failure，不放回 retry queue。

---

## Part 5: 交叉學習 — Resonance 的優秀實踐

### 5.1 Blog 應該學習的

#### 1. Prompt Template Injection

**Resonance 做法**：
```go
prompt := strings.ReplaceAll(baseTemplate, "{{LANGUAGE_STYLE_BLOCK}}", styleBlock)
prompt = strings.ReplaceAll(prompt, "{{SOURCE_RELATIONSHIP_BLOCK}}", sourceBlock)
```

**好處**：
- 共用 block 可以跨 prompt 重用
- 語言切換只需替換 style block
- A/B testing 只需替換一個 block

**Blog 建議**：
`polish.txt` 和 `review.txt` 有共用的規則（保留 code blocks、保留技術術語）。
可以抽出 `{{PRESERVATION_BLOCK}}` 共用。

#### 2. JSON 解析容錯

**Resonance 做法**：4 階段 fallback parser。
**Blog 現狀**：直接 `json.Unmarshal`，失敗即 flow 失敗。

#### 3. Multi-Turn 輸出穩定

**Resonance 做法**：將 assistant 的歷史回覆包裝成期望的 JSON 格式，防止模型在多輪對話中格式漂移。
**Blog 適用場景**：目前 blog 的 flow 都是 single-turn，但如果未來做互動式 content review，這個模式很重要。

#### 4. 「Before You Write」思考清單

**Resonance 的 Weaver prompt**：
```
## 動筆之前（內在檢查清單）
- 這首詩的核心意象是什麼？
- 情感溫度是什麼？
- source 的骨頭是什麼？
- 什麼不該寫？
```

**Blog 建議**：
`content-strategy` 可以加上類似的思考清單：
```
## 建議之前（內在檢查清單）
- 用戶最近的寫作重心是什麼？
- RSS 趨勢反映的是真正的技術變化還是噪音？
- 建議的主題是否在用戶的能力圈內？
- 這個建議是否會帶來新讀者？
```

### 5.2 Resonance 可以學習 Blog 的

#### 1. Token Budget 機制

Resonance **沒有 token budget**。如果 Opus 被大量呼叫（novel 生成 40K tokens），成本可能失控。
Blog 的 atomic CAS budget 是一個值得 resonance 採用的模式。

#### 2. Persistent Job Queue

Resonance 的 story generation 是 in-memory background goroutine，沒有持久化。
如果 server 重啟，進行中的 generation 會丟失。Blog 的 `flow_runs` 表 + cron retry 是更穩健的設計。

#### 3. Cron 排程框架

Resonance 沒有排程任務。Blog 的 cron 排程（morning brief、weekly review、content strategy）展示了 AI 如何做主動式知識管理，不只是被動回應。

#### 4. Embedding + 向量搜尋

Blog 的 `content-review` flow 生成 embedding 並存入 pgvector，支援相似內容推薦。
Resonance 目前沒有 embedding 能力。

---

## Part 6: Resonance Prompt 問題指出

### 6.1 Weaver Prompt 的 Temperature 風險

**Resonance** 的 Weaver 使用 **temp=0.9**（接近最大值）生成文學作品。
這是有意的（追求創意多樣性），但：

- 在 novel 模式下（40K tokens），高 temperature 的累積偏移會更嚴重
- 生成的後半段可能與前半段風格不一致
- 沒有 mid-generation 檢查點

**建議**：Novel 模式考慮分段生成（chapter by chapter），每段可以校正方向。

### 6.2 Search Tool 的強制性

**Resonance** 的 prompt 要求「任何事實性聲明必須先搜尋」，但這是 prompt 層的軟約束。
AI 可能跳過搜尋直接回答。

**建議**：在 Go 層檢查 tool call 記錄，如果回覆包含作品資訊但沒有 tool call，觸發 retry 或警告。

### 6.3 Moderation 的語言覆蓋

**Resonance** 支援 zh-TW、ja、en 三種語言的 moderation。
但 moderation prompt 本身是英文的，對中文和日文的 nuance 可能不夠敏感。

---

## Part 7: 具體行動建議（按優先順序）

### P0 — 立即修復

| # | 問題 | 修復方式 |
|---|------|----------|
| 1 | `build-log` 使用 `Generate()` 而非 `GenerateData[T]()` | 改用 `GenerateData[BuildLogResult]()` |
| 2 | 沒有 JSON 解析容錯 | 實作 `parseJSONLoose` utility（從 resonance 移植） |
| 3 | Content policy block 被 retry | 在 runner 中檢查 finish reason，permanent fail |

### P1 — 短期改善

| # | 問題 | 修復方式 |
|---|------|----------|
| 4 | `review.txt` 缺少 level 判斷標準 | 擴充 prompt（見 2.3 節建議） |
| 5 | `excerpt.txt` 過於簡略 | 擴充 prompt（見 2.3 節建議） |
| 6 | `tags.txt` 缺少分類策略 | 擴充 prompt（見 2.3 節建議） |
| 7 | 高 temp + JSON 輸出不穩定 | 降低 bookmark/build-log 的 temp 或改用 `GenerateData` |

### P2 — 中期優化

| # | 問題 | 修復方式 |
|---|------|----------|
| 8 | 無 Tool 整合 | 為 bookmark 增加 URL 驗證 tool |
| 9 | Prompt 共用 block 缺失 | 實作 template injection 模式 |
| 10 | Token 使用量不追蹤 | 讀取 `resp.Usage()` 並 log |
| 11 | `content-review` 粒度過粗 | 考慮拆分為 3 個獨立 flow |

### P3 — 長期考慮

| # | 問題 | 修復方式 |
|---|------|----------|
| 12 | 無 Eval 框架 | 參考 resonance 的 LLM-as-Judge 模式 |
| 13 | 無 content-strategy search | 增加 trending topic search tool |
| 14 | Flow composition 缺失 | 實作 flow-calls-flow 模式 |

---

## Part 8: 審查結論

### 評分總結

| 維度 | Blog | Resonance | 說明 |
|------|------|-----------|------|
| **架構穩健性** | A | B+ | Blog 的 persistent runner + retry + budget 更完整 |
| **Prompt 工程深度** | B- | A | Resonance 的 prompt 遠更精緻和結構化 |
| **Tool 整合** | D | B+ | Blog 零 tool，resonance 有 web search |
| **Flow 語意設計** | B | A- | Resonance 的 flow composition 更靈活 |
| **生產穩定性** | A- | B | Blog 的 graceful degradation 和 alert 更成熟 |
| **可測試性** | A- | A- | 兩者都有完整 mock 模式 |
| **可觀測性** | B+ | B | Blog 有 slog + alert，兩者都用 genkit tracing |
| **成本控制** | A | C | Blog 有 budget，resonance 無限制 |

### 核心結論

1. **Blog 的基礎設施（runner, budget, retry, alert）是優秀的**，但 prompt 工程和 AI 應用深度有明顯提升空間
2. **Resonance 的 prompt 工程是值得學習的標竿**，特別是行為規範式 prompt、shared bans、template injection
3. **Tool 整合是 blog 最大的缺口**，也是最容易產生差異化價值的改進方向
4. **兩個專案可以互相學習**：blog 的基礎設施 → resonance，resonance 的 prompt 深度 → blog

---

*This report is designed for dual review by Claude and Gemini. Reviewers should focus on: (1) whether the identified issues are accurate, (2) whether the priority ordering is correct, (3) whether the suggested fixes are practical, (4) additional issues not caught in this audit.*
