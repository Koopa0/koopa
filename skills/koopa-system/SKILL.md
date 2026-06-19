---
name: koopa-system
description: "Koopa Studio 系統操作手冊 — MCP 工具使用、角色定位、決策政策。當 Claude Desktop Cowork 中的任何 agent（planner、learning-studio）需要理解系統架構、選擇正確的 MCP 工具（15 個，canonical list 在 internal/mcp/ops/catalog.go::All()）、或審視自身角色定位時使用。也適用於系統審計、工具需求分析、instruction 優化。觸發場景：agent 不確定該用哪個工具、需要判斷 entity 建立規則（commitment 走 admin 表單）、需要角色特定的工作流指引。"
---

# Koopa System — Agent Operating Manual

本 skill 為 koopa 知識引擎中每個 AI agent 提供操作指引。
根據你的 `as` identity 載入對應手冊。

## Identity Resolution

根據你的 Project Instructions 中的 `as` 值確定身份：

| `as` value | Role | Reference |
|---|---|---|
| `planner` | 規劃 — 晨間 briefing + 候選日計畫 | [references/planner.md](references/planner.md) |
| `learning-studio` | 學習教練 — session、attempt、學習計畫 | [references/learning.md](references/learning.md) |

**Read your role's reference file first.** Then consult shared references as needed.

> **agent MCP surface 是 15 個工具**（canonical list：`internal/mcp/ops/catalog.go::All()`）。
> 沒有跨 agent 協調三元組（task / task_message / artifact）、沒有 report-lane、
> content 發布生命週期也不在 MCP 上。委派與內容發布走 admin HTTP 表單（人類操作），
> 不是 MCP 工具。agent 之間不透過 MCP 互傳指令；協調由人類（Koopa）擔任 router。

## Shared References

| File | When to read |
|---|---|
| [references/tools.md](references/tools.md) | 查工具參數、annotation、input/output schema（generated from `catalog.go`） |
| [references/decision-policy.md](references/decision-policy.md) | 判斷 intent routing、maturity assessment、entity ownership |

## Core Invariants

Every agent must know:

1. **Commitment 啟用走 admin，但 area / goal 可 propose inert draft** — project, milestone, hypothesis, learning_plan, learning_domain 沒有 MCP 建立路徑；這些高承諾實體由 Koopa 透過 admin HTTP 表單建立（`POST /api/admin/commitment/goals`、`/goals/{id}/milestones`、`/api/admin/commitment/projects`、`/api/admin/learning/plans`、`/api/admin/learning/domains`）。**例外**：agent 可用 `propose_area` / `propose_goal` / `draft_hypothesis` 起草 **inert draft**（status=proposed/draft，完全惰性 — 不進 brief / Today / active 讀取），但 endorse / activate / reject / 刪除全在 admin，Koopa 是唯一啟用者。其餘 commitment agent 只在對話中起草、提出建議，**不寫入**。
2. **Caller identity** — 每個 tool call 帶 `as: "<your-name>"`
3. **No auto-carryover** — 昨天未完成的 daily plan 不自動延遲，使用者主動決定
4. **Maturity gate** — M0（vague）不寫任何東西；M1 只 `capture_inbox`；M2+ commitment 由 Koopa 在 admin 表單建立
5. **Intent-first routing** — 評估使用者意圖信號，不做場景分類；first match wins
6. **Agent memory ≠ system entity** — agent 的內部敘事 / 計畫 / 反思寫進 agent 自己的 `.md` 檔（agent_notes feature 已退役）。`note`（Zettelkasten，`notes` 表）才是系統內可檢索的知識 artifact，走 `create_note` / `update_note`。
7. **Vocabulary discipline** — `todo`（個人 GTD，`capture_inbox`）≠ agent 的 `.md` memory；`note`（slug-addressable Zettelkasten）≠ agent 的 `.md` memory；`hypothesis`（可證偽主張）≠ reflection（敘事，寫進 `.md`）

## System Architecture (Minimal)

```
RSS feeds ──fetch──► feed_entries ──curate (admin UI)──► contents
Admin HTTP forms ──► contents (article / essay / build-log / til / digest) — 發布生命週期人類掌握
MCP create_note  ──► notes    (solve-note / concept-note / reading-note / ...)
                       kind + maturity (seed → evergreen → archived)

Agents ──daily work──► todos ──plan_day──► daily_plan_items
       ──learning──► learning_sessions → attempts → observations → mastery
       ──knowledge artifact──► notes (slug-addressable, search-indexed, Zettelkasten)
       ──own memory──► agent 自己的 .md（不是系統 entity）

Koopa (human) ──admin HTTP──► goals / projects / milestones / hypotheses / learning_plans / learning_domains
```

Domain model: **PARA** (Areas → Goals → Milestones → Projects) + **GTD** (inbox → todo → in_progress → done).
Commitment 實體（goal / project / milestone / hypothesis / learning_plan / learning_domain）由人類在 admin 表單啟用，不在 MCP surface 建立。例外：`propose_area` / `propose_goal` / `draft_hypothesis` 讓 agent 起草 inert draft（status=proposed/draft，完全惰性），Koopa 在 admin endorse / activate / reject。

## 語意切分（絕不混用）

| 分類 A | 分類 B | 測試 |
|---|---|---|
| `todos`（個人 GTD，MCP `capture_inbox`） | agent 自己的 `.md` memory | 是具體可完成的工作項？ |
| agent 自己的 `.md`（runtime 敘事 / 計畫 / 反思） | `notes`（長期 Zettelkasten artifact，`create_note`） | 有 slug、需跨 session 在系統內被檢索？ |
| `learning_targets`（要學的） | `notes(kind='solve-note')`（學完寫的） | 在筆記之前就存在？ |
| `concepts`（診斷本體） | `tags`（內容分類） | 代表可診斷的能力？ |
| `hypothesis`（可證偽主張，admin 建立） | reflection（敘事，寫進 agent `.md`） | 有 invalidation_condition？ |

## 如果找不到對應的工具該怎麼辦

優先順序：

1. 確認是否有存在的 entity 可以更新（`manage_plan(update_entry)`、`update_note` 等）
2. 確認該操作是否已移到 admin HTTP 表單（commitment 建立、content 發布、todo 狀態推進）— 若是，留在對話請 Koopa 在 admin UI 處理
3. 確認是否屬於 M0-M1（只能留在對話，不寫入）
4. 如果真的需要新 tool — **不要發明**，請留在對話並告訴使用者需要補什麼能力
