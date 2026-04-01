# LeetCode Adaptive Mastery System — 設計文件

## 解決什麼問題

Learning Coach（Claude.ai）原本只能看到 **pattern 級別** 的學習數據：「binary-search 做了 3 題，2 題 ac-independent」。但 LeetCode 精熟度是 **多維度** 的 — 一道題涉及多個概念，每個概念的掌握程度不同。Coach 缺乏 concept 級別的粒度來做好 adaptive teaching decisions。

具體痛點：

1. **無法區分「會了」和「被引導後才會」** — ac-with-hints 只說結果，不說哪個環節被引導
2. **弱點追蹤斷裂** — weakness tags 存在但從未被 persist 到 content_tags，整個 tag-based aggregation pipeline 是斷的
3. **沒有題目關聯性** — 做完 #33 (Search in Rotated Sorted Array) 不知道下一步該試 #81 (with duplicates) 還是 #153 (find minimum)
4. **Session startup 要 3-4 個 tool calls** — get_coverage_matrix + get_tag_summary + get_weakness_trend，每次都重複

## 設計決策

### 1. Concept-level mastery tracking via metadata, not tags

每筆 TIL 的 `ai_metadata` JSONB 新增 `concept_breakdown`：

```json
{
  "concept_breakdown": [
    {"concept": "Recognize binary search applicability", "mastery": "independent"},
    {"concept": "Rotated array has one sorted half", "mastery": "guided", "coaching_hint": "如果你把 array 從 mid 切開，兩半有什麼特別的？"}
  ]
}
```

5 級 mastery enum：`independent` → `independent_after_hint` → `guided` → `told` → `not_explored`

**為什麼用 JSONB 而不是獨立 table？** 200 TILs × 3 concepts = 600 筆，`jsonb_array_elements` aggregation < 10ms。獨立 concepts table 解決的是不存在的效能問題，卻引入 migration、sync logic、entity lifecycle 的真實複雜度。

### 2. Exact string match for concept grouping, not embeddings

系統有 embedding infrastructure（768-dim via Genkit，hourly cron），但 **不用在 concept matching 上**。

原因：embeddings 是為整篇文章語意設計的，10-30 字的 concept string（「Modified binary search condition for rotation」）信號太弱，matching 品質不可預測。Coach 是單一 Claude instance，可以維持用詞一致。需要 fuzzy grouping 時，Coach 在 client side 做語意比對比 embedding cosine similarity 更準。

### 3. Backend 算 stage，同時回傳 raw signals

`mastery_map` 的 stage（unexplored/struggling/developing/solid）由 backend deterministic 計算，但同時回傳 `stage_signals`（problems_solved, ac_rate, guided_ratio 等原始數字）。

Coach 可以 default 顯示 stage，但有額外 context 時 override — 例如「Koopa 說他週末自己讀了 DP」，Coach 可以把 struggling 升成 developing 並解釋原因。

### 4. FSRS state transition 作為 regression 主信號

Regression detection 不用「比較最近 3 題 vs 之前 3 題」的粗糙 heuristic，而是直接從 FSRS review logs 讀取：`state = Review AND rating = Again` = 「以為會了但忘了」。

這個 signal 是 per-card 的（card 可以帶 `tag = weakness:approach-selection`），而且資料已經存在，不需要新 logging。Simple heuristic 作為 secondary signal 用在 FSRS 資料稀疏的 pattern。

### 5. 兩種 tag 的 lifecycle 分離

| Tag 來源 | Validation | 進入 tags table 的方式 | Resolution pipeline |
|----------|-----------|----------------------|-------------------|
| LeetCode canonical | vocab.go strict enum | Migration seed（59 tags） | Slug match → found → persist |
| Obsidian raw tags | 無限制 | Admin 手動建立 | Unmapped → admin review queue |

這是在 production testing 中發現的架構問題 — `tags` table 從未被初始化（0 筆），導致所有 tag resolution 都走到 unmapped → skip。修法是 migration seed，跟 `topics` table 的 seed pattern 一致。

## 做到什麼事情

### 3 個新 MCP 工具

**`mastery_map`** — 一次呼叫取得全局視圖
- Per-pattern stage 計算（4 級，有明確的晉級條件）
- Concept mastery 聚合（independent/guided/told 各幾個）
- Weak concepts 列表（guided/told 的概念 + coaching hint，按時間倒序）
- Unexplored approaches（還沒試過的解法）
- Variation coverage（做過哪些題、linked follow-ups 有哪些沒做）
- Regression signals（FSRS Review→Again + result trend）
- Raw stage_signals（讓 Coach 可以 override）

**`concept_gaps`** — 跨 pattern systemic weakness
- 掃描所有 TIL 的 concept_breakdown，找出跨 2+ 題出現 guided/told 的概念
- Exact match grouping（normalized lowercase + trim）
- Coaching history（所有 coaching hints 的 flat list，按時間倒序）

**`variation_map`** — 題目關係圖
- 從 variation_links metadata 建 cluster graph
- Anchor problem + linked variations（標記 attempted/unattempted）
- Isolated problems（沒有 variation links 的題目）
- 驅動「你做了 A，下一步試 A'」推薦

### Enhanced 既有工具

- `coverage_matrix` 新增 difficulty_distribution + avg_concept_mastery
- `learning_timeline` 回傳 concept_breakdown, solve_context, variation_links
- `content_detail` 回傳 ai_metadata（原本缺失）

### MCP 命名規範重整

27 個 read-only tools 砍掉 `get_` prefix，1 個砍掉 `batch_` prefix。

規則：read-only → 名詞片語（`morning_context`, `mastery_map`），write → 動詞（`create_task`, `log_dev_session`），search/find → 保留動詞（`search_knowledge`）。

### Production bugs 修復

| Bug | Root cause | Fix |
|-----|-----------|-----|
| Tags 沒 persist | `logLearningSession` 有 TODO 從未實作 | 加 tag resolution + AddContentTag |
| Tags table 空 | Migration 漏了 seed data | 59 canonical tags seed 進 001 migration |
| Colon 被 strip | `tag.Slugify` char whitelist 沒有 `:` | 保留 colon 作為 namespace delimiter |
| content_detail crash | MCP SDK 把 json.RawMessage 推斷成 array schema | 改用 map[string]any |

## 數字

- **+1783 / -217 lines** across 27 files
- **3 new MCP tools**, 0 new packages, 0 new tables
- **59 canonical tags** seeded
- **1434 lines of tests**（mastery_test.go + metadata_test.go，197 test cases）
- **54 total MCP tools**（was 49, +3 mastery tools, +2 skip/completion history from previous work）

## Coach 如何使用

### Session startup
```
mastery_map(project="leetcode")
→ 看 per-pattern stage，決定今天練哪個 pattern
→ 看 weak_concepts，決定要不要 revisit 之前被 guided 的概念
→ 看 variation_coverage.known_follow_ups，推薦下一題
```

### Session 中寫入
```
log_learning_session(
  metadata={
    concept_breakdown: [{concept: "...", mastery: "guided", coaching_hint: "..."}],
    variation_links: [{problem_number: 81, relationship: "harder_variant"}],
    solve_context: {stuck_points: [{at: "...", resolved_by: "coaching_hint"}]}
  }
)
```

### 跨 session 分析
```
concept_gaps(project="leetcode")
→ 找出跨多題反覆出現的 systemic weakness
→ coaching_history 回顧所有給過的 hint
```
