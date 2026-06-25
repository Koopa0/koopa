---
name: koopa-system
description: "Koopa Studio 系統操作手冊 — MCP 工具使用、角色定位、決策政策。當 Claude Desktop Cowork 中的 planner agent 需要理解系統架構、選擇正確的 MCP 工具（15 個，canonical list 在 internal/mcp/ops/catalog.go::All()）、或審視自身角色定位時使用。也適用於系統審計、工具需求分析、instruction 優化。觸發場景：agent 不確定該用哪個工具、需要判斷 entity 建立規則（commitment 走 propose_* inert draft，Koopa 在 admin activate）、需要角色特定的工作流指引。"
---

# Koopa System — Agent Operating Manual

本 skill 為 koopa 知識引擎中每個 AI agent 提供操作指引。
根據你的 `as` identity 載入對應手冊。

## Identity Resolution

根據你的 Project Instructions 中的 `as` 值確定身份：

| `as` value | Role | Reference |
|---|---|---|
| `planner` | 規劃 — 晨間 briefing + 候選日計畫 + PARA 提案 | [references/planner.md](references/planner.md) |

**Read your role's reference file first.** Then consult shared references as needed.

> **agent MCP surface 是 15 個工具**（canonical list：`internal/mcp/ops/catalog.go::All()`）。
> `as` 只做 attribution（**無 tool-layer 授權**；存取邊界是 MCP transport — Option B）。
> 協調由人類（Koopa）擔任 router；委派在對話中完成。content 發布生命週期不在 MCP 上 —
> `propose_content` 只把完成的稿子推進審核佇列，publish 是 Koopa 的 admin 動作。高承諾
> 實體（area / goal / project）由 agent `propose_*` 起 inert draft，Koopa 在 admin activate。

## Shared References

| File | When to read |
|---|---|
| [references/tools.md](references/tools.md) | 查工具參數、annotation、input/output schema（generated from `catalog.go`） |
| [references/decision-policy.md](references/decision-policy.md) | 判斷 intent routing、maturity assessment、entity ownership |

## Core Invariants

Every agent must know:

1. **Commitment 啟用走 admin，但 area / goal / project 可 propose inert draft** — milestone 沒有 MCP 建立路徑，由 Koopa 透過 admin HTTP 表單建立（`POST /api/admin/commitment/goals/{id}/milestones`）。agent 可用 `propose_area` / `propose_goal` / `propose_project` 起草 **inert draft**（status=proposed，完全惰性 — 不進 brief / Today / active 讀取），但 activate（proposed→active / in_progress）/ reject（hard delete）全在 admin，Koopa 是唯一啟用者。
2. **Caller identity** — 每個 tool call 帶 `as: "<your-name>"`
3. **No auto-carryover** — 昨天未完成的 daily plan 不自動延遲，使用者主動決定
4. **Maturity gate** — M0（vague）不寫任何東西；M1 只 `capture_inbox`；M2+ 用 `propose_*` 起 inert draft，Koopa 在 admin activate
5. **Intent-first routing** — 評估使用者意圖信號，不做場景分類；first match wins
6. **Agent memory ≠ system entity** — agent 的內部敘事 / 計畫 / 反思寫進 agent 自己的 `.md` 檔。
7. **Vocabulary discipline** — `todo`（個人 GTD，`capture_inbox`）≠ agent 的 `.md` memory；`content`（可發布文章，`propose_content` 進審核佇列）≠ reflection（敘事，寫進 `.md`）

## System Architecture (Minimal)

```
RSS feeds ──fetch──► feed_entries ──curate (admin UI)──► contents
Agents ──propose_content──► contents (status=review) ──publish (admin)──► 公開
Admin HTTP forms ──► contents (article / essay / build-log / til / digest) — 發布生命週期人類掌握

Agents ──daily work──► todos ──plan_day──► daily_plan_items
       ──set_todo_recurrence──► 自建 todo 設週幾 / interval 循環（compute-on-read，每逢符合日進 brief；resolve_todo done = 完成當日 occurrence、續循環）
       ──propose_*──► areas / goals (+ milestones) / projects (status=proposed, inert)
       ──own memory──► agent 自己的 .md（不是系統 entity）

Koopa (human) ──admin triage──► activate (proposed→active / in_progress) / reject
              ──admin HTTP──► milestones / content publish
```

Domain model: **PARA** (Areas → Goals → Milestones → Projects) + **GTD** (inbox → todo → in_progress → done).
高承諾實體：milestone 由人類在 admin 表單建立；area / goal / project 由 agent `propose_*` 起 inert draft（status=proposed，完全惰性），Koopa 在 admin activate / reject。

## 語意切分（絕不混用）

| 分類 A | 分類 B | 測試 |
|---|---|---|
| `todos`（個人 GTD，MCP `capture_inbox`） | agent 自己的 `.md` memory | 是具體可完成的工作項？ |
| `content`（可發布文章，`propose_content` 進審核佇列） | reflection（敘事，寫進 agent `.md`） | 是完成、可給人讀的稿子？ |
| `propose_*` inert draft（status=proposed） | active commitment（Koopa 在 admin activate） | 已被 Koopa 啟用了嗎？ |

## 如果找不到對應的工具該怎麼辦

優先順序：

1. 確認該操作是否在 admin HTTP（milestone 建立、commitment activate / reject、content publish、Koopa 自己的 todo 狀態推進）— 若是，留在對話請 Koopa 在 admin UI 處理
2. 確認是否屬於 M0-M1（只能留在對話，不寫入）
3. 如果真的需要新 tool — **不要發明**，請留在對話並告訴使用者需要補什麼能力
