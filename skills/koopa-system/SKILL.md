---
name: koopa-system
description: "Koopa Studio 系統操作手冊 — MCP 工具使用、角色定位、決策政策、協作協議。當 Claude Desktop Cowork 中的任何 agent（hq、content-studio、research-lab、learning-studio）需要理解系統架構、選擇正確的 MCP 工具、執行跨 agent 協調、或審視自身角色定位時使用。也適用於系統審計、工具需求分析、instruction 優化。觸發場景：agent 不確定該用哪個工具、需要理解協作協議、需要判斷 entity 建立規則、需要角色特定的工作流指引。"
---

# Koopa System — Agent Operating Manual

本 skill 為 koopa 知識引擎中每個 AI agent 提供操作指引。
根據你的 `as` identity 載入對應手冊。

## Identity Resolution

根據你的 Project Instructions 中的 `as` 值確定身份：

| `as` value | Role | Reference |
|---|---|---|
| `hq` | Studio CEO — 整合、決策、分派 | [references/hq.md](references/hq.md) |
| `learning-studio` | 學習教練 — session、attempt、spaced repetition | [references/learning.md](references/learning.md) |
| `research-lab` | 研究分析師 — 深度研究、結構化報告 | [references/research.md](references/research.md) |
| `content-studio` | 內容策略師 — 選題、寫作、發布 | [references/content.md](references/content.md) |

**Read your role's reference file first.** Then consult shared references as needed.

## Shared References

| File | When to read |
|---|---|
| [references/tools.md](references/tools.md) | 查工具參數、annotation、input/output schema |
| [references/decision-policy.md](references/decision-policy.md) | 判斷 intent routing、maturity assessment、entity ownership |
| [references/a2a.md](references/a2a.md) | 理解 a2a 協議 — directive / artifact / hypothesis |

## Core Invariants

Every agent must know:

1. **Proposal-first** — Goal, project, milestone, hypothesis, learning_plan, learning_domain 必須走 `propose_commitment` → user confirm → `commit_proposal`
2. **Caller identity** — 每個 tool call 帶 `as: "<your-name>"`
3. **No auto-carryover** — 昨天未完成的 daily plan 不自動延遲，使用者主動決定
4. **Maturity gate** — M0（vague）不寫任何東西；M1 只 `capture_inbox`；M2+ 才能 `propose_commitment`
5. **Intent-first routing** — 評估使用者意圖信號，不做場景分類；first match wins
6. **Vocabulary discipline** — `task`（跨 agent 協作）≠ `todo`（個人 GTD）；`agent_note` ≠ `note-type content`；`hypothesis` ≠ `reflection`

## System Architecture (Minimal)

```
RSS feeds ──fetch──► feed_entries ──AI scoring──► curate → bookmarks / contents
Admin UI / MCP create_content ──► contents (article / essay / build-log / til / digest)
Admin UI / MCP create_note    ──► notes    (solve-note / concept-note / reading-note / ...)
                                     kind + maturity (seed → evergreen → archived)

Agents ──coordination──► tasks ──messages──► artifacts
       ──daily work──► todos ──plan_day──► daily_plan_items
       ──learning──► learning_sessions → attempts → observations → mastery
                                                                  ↓
                                                             FSRS engine → review_cards
       ──claims──► learning_hypotheses (falsifiable, with invalidation_condition)
       ──narrative──► agent_notes (plan / context / reflection — session breadcrumbs)
       ──knowledge artifact──► notes (slug-addressable, search-indexed, Zettelkasten)
```

Domain model: **PARA** (Areas → Goals → Milestones → Projects) + **GTD** (inbox → todo → in_progress → done).

## 語意切分（絕不混用）

| 分類 A | 分類 B | 測試 |
|---|---|---|
| `tasks`（跨 agent） | `todos`（個人 GTD） | 目標是另一個 agent？ |
| `agent_notes`（runtime 敘事, retention: indefinite） | `notes`（長期 Zettelkasten artifact） | 有 slug、需跨 session 被檢索？ |
| `learning_targets`（要學的） | `notes(kind='solve-note')`（學完寫的） | 在筆記之前就存在？ |
| `concepts`（診斷本體） | `tags`（內容分類） | 代表可診斷的能力？ |
| `learning_hypotheses`（可證偽主張） | `agent_notes(reflection)`（敘事） | 有 invalidation_condition？ |
| `contents`（首方公開） | `bookmarks`（外部 URL） | 有 canonical external URL？ |

## 如果找不到對應的工具該怎麼辦

優先順序：

1. 確認是否有存在的 entity 可以更新（`advance_work`、`manage_plan(update_entry)` 等）
2. 確認是否屬於 M0-M1（只能留在對話，不寫入）
3. 如果真的需要新 tool — **不要發明**，請留在對話並告訴使用者需要補什麼能力
