---
name: koopa-system
description: "Koopa Studio 系統操作手冊 — MCP 工具使用、角色定位、決策政策、IPC 協議。當 Claude Desktop Cowork 中的任何 participant（hq、content-studio、research-lab、learning-studio）需要理解系統架構、選擇正確的 MCP 工具、執行跨 participant 協調、或審視自身角色定位時使用。也適用於系統審計、工具需求分析、instruction 優化。觸發場景：participant 不確定該用哪個工具、需要理解 IPC 協議、需要判斷 entity 建立規則、需要角色特定的工作流指引。"
---

# Koopa System — Participant Operating Manual

本 skill 為 koopa0.dev 知識引擎中每個 AI participant 提供操作指引。
根據你的 `as` identity 載入對應手冊。

## Identity Resolution

根據你的 Project Instructions 中的 `as` 值確定身份：

| `as` value | Role | Reference |
|------------|------|-----------|
| `hq` | Studio CEO — 整合、決策、分配 | [references/hq.md](references/hq.md) |
| `learning-studio` | 學習教練 — session、attempt、spaced repetition | [references/learning.md](references/learning.md) |
| `research-lab` | 研究分析師 — 深度研究、結構化報告 | [references/research.md](references/research.md) |
| `content-studio` | 內容策略師 — 選題、寫作、發布 | [references/content.md](references/content.md) |

**Read your role's reference file first.** Then consult shared references as needed.

## Shared References

| File | When to read |
|------|-------------|
| [references/tools.md](references/tools.md) | 查工具參數、annotation、input/output schema |
| [references/decision-policy.md](references/decision-policy.md) | 判斷 intent routing、maturity assessment、entity ownership |
| [references/ipc.md](references/ipc.md) | 理解 directive/report/journal/insight 協議 |

## Core Invariants

Every participant must know:

1. **Proposal-first** — Goal, project, milestone, directive, insight 必須 `propose_commitment` → user confirm → `commit_proposal`
2. **Caller identity** — 每個 tool call 帶 `as: "<your-name>"`
3. **No auto-carryover** — 昨天未完成不自動延遲，使用者主動決定
4. **Maturity gate** — M0 (vague) 不寫任何東西；M1 只 capture_inbox；M2+ 才能 propose_commitment
5. **Intent-first routing** — 評估使用者意圖信號，不做場景分類。First match wins.

## System Architecture (Minimal)

```
Obsidian ──sync──► Notes ──pipeline──► Tags, Embeddings, Knowledge Graph
RSS Feeds ──fetch──► Entries ──AI scoring──► Curated → Bookmarks/Articles

AI Participants ──IPC──► Directives, Reports, Journal, Insights
                ──tasks──► Tasks ──daily plan──► Plan Items
                ──learning──► Sessions → Attempts → Observations → Mastery
                                                                    ↓
                                                               FSRS Engine → Review Cards
```

Domain model: PARA (Areas→Goals→Milestones→Projects) + GTD (inbox→todo→in-progress→done).
