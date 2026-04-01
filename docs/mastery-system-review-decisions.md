# LeetCode Adaptive Mastery System — 審查決策紀錄

> 三份獨立審查的統一結論和後續 action items。
> 審查日期：2026-04-01
> 審查者：Claude Devil's Advocate、Gemini、Claude Deep Dive (ITS/BKT)

---

## 審查共識：核心風險

**Write path 的一致性決定 read path 的品質。** 三個新 tool（mastery_map, concept_gaps, variation_map）全部是 read-only aggregation — 它們忠實地彙整 `log_learning_session` 寫入的資料。如果寫入端不一致，讀取端的分析會靜悄悄地變差。

三份審查都指向的具體風險：
1. **Concept naming 飄移** — 同一個概念在不同 session 用不同措辭，exact match 無法 group
2. **Mastery 判定模糊** — `independent_after_hint` vs `guided` 的邊界是 LLM 主觀判斷
3. **缺乏校準機制** — 沒有信號告訴你資料品質在下降

---

## 已完成的 Mitigation

| 層 | 措施 | 狀態 |
|----|------|------|
| Instructions | Mastery 判定表（5 級行為定義） | ✅ 已加入 Coach project instructions |
| Instructions | Concept naming convention（[動詞]+[對象] 格式） | ✅ 已加入 |
| Instructions | Variation links 提醒（主動關聯 classic variations） | ✅ 已加入 |
| Data | `mastery_map` 回傳 `known_concepts` 列表 | ✅ 已實作 (commit 9a73d16) |
| Data | 59 canonical tags seeded 進 tags table | ✅ 已實作 |
| Data | `tag.Slugify` 保留 colon（namespace delimiter） | ✅ 已修 |

---

## 未來 Checkpoints（按資料量觸發）

### Checkpoint 1：20 題

**觸發條件：** `coverage_matrix` 顯示 total_entries >= 20

**驗證項目：**
- [ ] 檢查 `concept_gaps` 的 systemic_gaps 數量 — 如果為 0 或 1，可能是 fragmentation 導致 under-count
- [ ] 手動檢查 `known_concepts` 列表 — 是否有明顯的重複措辭（同一概念不同寫法）
- [ ] 評估 fragmentation 程度：`SELECT concept, count(*) FROM (SELECT jsonb_array_elements(ai_metadata->'concept_breakdown')->>'concept' AS concept FROM contents WHERE type='til') sub GROUP BY concept ORDER BY count DESC`

**如果 fragmentation 嚴重（> 30% 概念只出現 1 次）：**
- 實作 `pg_trgm` fuzzy dedup：在 `concept_gaps` 的 aggregation 層用 `similarity()` merge cosine > 0.85 的 concepts
- PostgreSQL 內建 `pg_trgm` extension，不需要額外依賴

### Checkpoint 2：50 題

**觸發條件：** `coverage_matrix` 顯示 total_entries >= 50

**驗證項目：**
- [ ] A/B validation：用純 raw signals + 最近 5 題 full TIL notes 做一次 coaching session，跟用 mastery_map 的 concept data 做一次比較。看 coaching quality 有沒有 observable difference
- [ ] 評估是否需要 PFA（Performance Factor Analysis）取代 rule-based stage：如果有 5+ 個 concept 各有 5+ 次觀測，PFA 的 logistic regression 可以提供更精確的 mastery 估計
- [ ] 檢查 FSRS regression signal 是否有真實數據（Review→Again 的 card 數量）

### Checkpoint 3：100 題

**觸發條件：** `coverage_matrix` 顯示 total_entries >= 100

**驗證項目：**
- [ ] 評估 `mastery_map` response size — 跨 pattern 重複是否導致 response 過大
- [ ] 考慮加 `primary_pattern` 欄位做去重
- [ ] 評估 concept naming convention 的長期效果

---

## 審查發現 × 決策紀錄

### #1 Concept Naming Fragmentation（三份共識）

| 審查者 | 建議 |
|--------|------|
| Claude DA | Revisit — canonical vocab 或放棄 backend aggregation |
| Gemini | 在 mastery_map 回傳 existing_concepts，Coach 優先複用 |
| Claude Deep | pg_trgm 或 Levenshtein fuzzy dedup |

**決策：** 採用 Gemini 方案（`known_concepts`），已實作。20 題後評估是否需要 pg_trgm。不做 canonical concept vocabulary（概念無法窮舉）。不放棄 backend aggregation。

**理由：** `known_concepts` 是最低成本的 mitigation — backend 一個 string dedup 函數，instructions 一段規則。pg_trgm 保留為 Checkpoint 1 的候選方案。

### #2 Mastery Enum 精確度

| 審查者 | 建議 |
|--------|------|
| Claude DA | 砍成 3 級（independent / assisted / told） |
| Gemini | 加行為定義到 prompt |
| Claude Deep | 考慮 continuous confidence 取代 discrete enum |

**決策：** 保留 5 級，加行為判定表（已完成）。不砍級，不換 continuous model。

**理由：** 5 級的表達力對 Coach 寫入有價值。問題在 aggregation 怎麼用，不在 enum 本身。判定表解決了邊界模糊問題。Continuous model 在 < 50 觀測時不比 discrete 好。

### #3 ITS/BKT 領域對照（Claude Deep 獨有）

**核心 insight：** 「你在 scheduling 上選了 FSRS（continuous model），但在 mastery tracking 上用的是 SM-2 等級的 heuristic。」

**決策：** 記錄但不行動。50 題後評估 PFA。

**理由：** BKT 需要 per-KC 多次觀測。PFA（Performance Factor Analysis）比 BKT 簡單（logistic regression），只需要 success/failure counts，跟現有 `concept_mastery` counts 結構相容。但現在每個 concept 可能只有 1-2 次觀測，概率模型也會 underfit。

**相關學術 reference：**
- BKT: Corbett & Anderson (1994) — Knowledge Tracing
- PFA: Pavlik, Cen & Koedinger (2009) — Performance Factor Analysis
- FSRS: Ye (2022) — Free Spaced Repetition Scheduler
- DKT: Piech et al. (2015) — Deep Knowledge Tracing
- Code-DKT: programming-specific DKT variant
- Intervention-BKT: adds instructional intervention modeling to BKT
- HLR: Settles & Meeder (2016) — Duolingo Half-Life Regression

### #4 Convergent vs Expansionary

**決策：** 功能已 ship，不回滾。但意識到這是 expansionary。接下來的工作回到 content production。

### #5 Variation Links Cold Start

| 審查者 | 建議 |
|--------|------|
| Gemini | 爬 LeetCode / NeetCode seed data |
| Claude Deep | NOTED（同 Gemini） |

**決策：** 不爬。Coach 的 training data 包含題目關係。Instructions 已加提醒。

### #6 FSRS Regression Signal

**決策：** 保留。Coach instructions 有 retrieval practice 流程。數據會隨 session 累積。

---

## 未驗證的最大假設

> Structured concept metadata 是否比 rich unstructured TIL notes 更能驅動 Claude 的 coaching decisions？

**驗證方法：** 50 題時做 A/B test — 一次用 mastery_map，一次用最近 5 題 full TIL body。比較 coaching quality。

**如果答案是 No：** concept_breakdown 寫入仍有價值（作為 session 紀錄），但三個 aggregation tools 的 ROI 需要重新評估。
