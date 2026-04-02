# Toolchain Integration Report — 2026-04-02

> Koopa Studio 工具鏈整合研究報告：Cowork 協作、Zed IDE 整合、GitHub Copilot 分工、Chrome DevTools

---

## 目錄

1. [現況盤點](#1-現況盤點)
2. [Cowork 多專案協作](#2-cowork-多專案協作)
3. [Zed IDE 整合方案](#3-zed-ide-整合方案)
4. [GitHub Copilot Coding Agent 分工](#4-github-copilot-coding-agent-分工)
5. [Chrome DevTools 整合](#5-chrome-devtools-整合)
6. [統一管理 UI 願景設計](#6-統一管理-ui-願景設計)
7. [建議行動計劃](#7-建議行動計劃)
8. [待決事項](#8-待決事項)
9. [資料來源](#9-資料來源)

---

## 1. 現況盤點

### 1.1 Cowork 專案（4 個）

| 專案 | 角色 | Instructions 位置 | MCP 連接 |
|------|------|-------------------|----------|
| Studio HQ | CEO / 指揮中心 | `docs/Koopa-HQ.md` | koopa0.dev MCP, Gmail, Google Calendar |
| Content Studio | 內容策略 + 編輯 | `docs/Koopa-Content-Studio.md` | koopa0.dev MCP |
| Research Lab | 研究分析 | `docs/Koopa-Research-Lab.md` | koopa0.dev MCP, Web Search, Scholar Gateway |
| Learning | 學習教練 | `docs/Koopa-Learning.md` | koopa0.dev MCP, Context7 |

### 1.2 跨專案通訊機制（已有）

```
HQ ──save_session_note(type="directive")──→ MCP DB
                                              │
Content Studio ←──session_notes(type="directive")──┤
Research Lab   ←──session_notes(type="directive")──┤
Learning       ←──session_notes(type="plan")───────┘
                      │
                      └──save_session_note(type="report")──→ MCP DB ──→ HQ 讀取
```

通訊已有基礎架構，但目前是**手動觸發**：每個 Cowork session 開始時主動拉 directive，結束時寫 report。沒有自動排程。

### 1.3 IDE 環境

- **主力 IDE**：Zed（唯一）
- **Claude Code**：CLI + Desktop（Cowork 模式）
- **Auggie MCP**：已連接（`mcp__auggie-mcp__codebase-retrieval`）
- **GitHub Copilot**：已有 subscription，Zed 已支援 GA

---

## 2. Cowork 多專案協作

### 2.1 Cowork Projects 能力與限制

**能力（2026-03 更新）：**
- 每個 Project 有獨立的 instructions、context folders、memory
- 支援 scheduled tasks（`/schedule`）
- 可連接 MCP connectors（Slack, 自定義 MCP 等）
- Memory 在 project 內持久化

**關鍵限制：**

| 限制 | 影響 | 解法 |
|------|------|------|
| **Memory 不跨 project** | HQ 的決策記憶不會自動同步到 Content Studio | 已有解法：透過 MCP `save_session_note` / `session_notes` 做異步通訊 |
| **Scheduled tasks 需要桌面 app 開啟且聚焦 Cowork** | 背景排程不可靠，已知 bug（[#36131](https://github.com/anthropics/claude-code/issues/36131)） | Cloud schedule（`claude.ai/code/scheduled`）跑在 Anthropic 雲端，不依賴本機 |
| **Projects 僅限本機，不可分享** | 無法多人協作（目前不影響，單人工作室） | N/A |
| **無原生跨 project 觸發機制** | HQ 無法自動觸發 Content Studio 執行任務 | 中間層：MCP DB 作為 message bus + 各 project 自己 poll |

### 2.2 排程策略

#### 方案 A：Cowork Desktop Scheduled Tasks（本機）

```
優點：配置簡單，UI 直覺
缺點：必須桌面 app 開啟且聚焦 Cowork view（已知 bug），電腦不能休眠
適合：開發時段內的定期任務
```

#### 方案 B：Cloud Scheduled Tasks（`claude.ai/code/scheduled`）

```
優點：跑在 Anthropic 雲端，不依賴本機，24/7 可用
缺點：最短間隔 1 小時，每次 run 是獨立 session（無跨 session memory，但可透過 MCP 讀寫狀態）
適合：每日 morning briefing、每週報告等固定節奏任務
```

#### 方案 C：混合策略（建議）

| 任務 | 平台 | 頻率 | 說明 |
|------|------|------|------|
| HQ Morning Briefing | Cloud Schedule | 每日 08:00 | `morning_context` → 產出 briefing → 寫 directive |
| Content Pipeline Check | Cloud Schedule | 每日 14:00 | 讀 directive → `list_content_queue` → RSS 監測 → 寫 report |
| Research Lab 產業掃描 | Cloud Schedule | 每週一 09:00 | RSS + web search → 產業動態摘要 → 寫 report |
| HQ Weekly Review | Cloud Schedule | 每週五 17:00 | `weekly_summary` + 各部門 report → 週報 |
| Learning | 手動觸發 | 按需 | 互動式學習不適合自動排程 |

### 2.3 跨 Project 協作流程（現行最佳實踐）

目前沒有找到完全對標的公開案例。你的架構（多角色 Cowork + MCP message bus）比社群大多數用法都先進。

**現行可用的協作模式：**

```
1. HQ schedule 跑完 → 寫 directive 到 MCP
2. Content Studio schedule 跑完 → 讀 directive → 執行 → 寫 report 到 MCP
3. HQ 下次 run 讀 report → 評估 → 決策

通訊延遲 = schedule 間隔（1-24 小時）
```

**社群框架參考（code-level orchestration，非 Cowork）：**
- [oh-my-claudecode](https://byteiota.com/oh-my-claudecode-multi-agent-orchestration-for-claude-code/) — 多 agent 框架
- [ruflo](https://github.com/ruvnet/ruflo) — 多 agent 任務分配
- [Agent Teams](https://code.claude.com/docs/en/agent-teams)（實驗性）— Claude Code CLI 內的多 agent，非 Cowork

這些都是工程導向的 agent team，不是 business role separation。你的模式更接近「虛擬團隊管理」。

### 2.4 優化建議

**短期（不寫 code）：**
1. 為 HQ 和 Content Studio 設定 Cloud Schedule
2. 統一各 project instructions 的 `note_type` 命名（目前 HQ 用 `"directive"`，Content Studio 檢查 `"ceo-directive"`，有不一致）
3. 在每個 project instructions 的 Session 啟動流程明確定義「讀哪些 note_type」和「寫哪些 note_type」

**中期（統一管理 UI，見第 6 節）：**
- 把各 Cowork project 的 schedule 定義存入 MCP
- koopa0.dev 前端做 dashboard 管理

---

## 3. Zed IDE 整合方案

### 3.1 MCP Server 整合

Zed 完整支援 MCP Tools 和 Prompts。在 `~/.config/zed/settings.json` 加入：

```jsonc
{
  "context_servers": {
    // koopa0.dev 知識引擎
    "koopa0-knowledge": {
      "command": "/path/to/koopa0-mcp-binary",
      "args": ["serve"],
      "env": {
        "DATABASE_URL": "your-connection-string"
      }
    },
    // Augment Context Engine
    "Augment-Context-Engine": {
      "command": "auggie",
      "args": ["--mcp", "--mcp-auto-workspace"],
      "env": {}
    }
  }
}
```

也可以用 Zed Agent Panel → Settings → "Add Custom Server" 按鈕手動加入。

**驗證方式**：Agent Panel settings 裡的 indicator dot — green = active。

### 3.2 GitHub Copilot in Zed

自 2026-02-19 GA。配置：

```jsonc
{
  // Edit prediction（inline completion）
  "edit_predictions": {
    "mode": "subtle",           // 或 "eager"
    "provider": {
      "name": "copilot"         // 或 "zeta"（Zed 預設）, "codestral"
    }
  },
  
  // Copilot Chat / Agent（ACP Agent）
  // Settings → GitHub Copilot Chat → Sign in
}
```

**分工建議**：見第 4 節。

### 3.3 Auggie CLI Extension

Zed marketplace 有 [Auggie CLI extension](https://zed.dev/extensions/auggie)，也可以用 MCP 方式手動配置。

Augment 另外也有 [ACP Agent](https://zed.dev/acp/agent/augment-code) 直接在 Zed Agent Panel 裡使用。

### 3.4 Zed 整合全景圖

```
┌─────────────────────────────────────────────┐
│                  Zed IDE                     │
│                                              │
│  ┌──────────────┐  ┌──────────────────────┐ │
│  │ Edit Area    │  │ Agent Panel          │ │
│  │              │  │                      │ │
│  │  Copilot     │  │  Claude (Zed Agent)  │ │
│  │  (inline     │  │  ├─ koopa0 MCP      │ │
│  │  completion) │  │  ├─ Auggie MCP      │ │
│  │              │  │  └─ other tools     │ │
│  │  Zeta        │  │                      │ │
│  │  (fallback)  │  │  Copilot ACP Agent  │ │
│  │              │  │  (coding agent)     │ │
│  └──────────────┘  └──────────────────────┘ │
│                                              │
│  ┌──────────────────────────────────────────┐│
│  │ Terminal                                  ││
│  │  Claude Code CLI                          ││
│  │  ├─ koopa0 MCP                           ││
│  │  ├─ Auggie MCP                           ││
│  │  ├─ go-spec agents (comprehend, etc.)    ││
│  │  └─ git workflow (commit, PR, verify)    ││
│  └──────────────────────────────────────────┘│
└─────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────┐
│ GitHub               │
│  Copilot Coding      │
│  Agent (cloud)       │
│  ├─ Issue → PR      │
│  ├─ Agentic Review  │
│  └─ Agents Tab      │
└─────────────────────┘
```

---

## 4. GitHub Copilot Coding Agent 分工

### 4.1 能力矩陣

| 能力 | Claude Code | Copilot Coding Agent | 最佳選擇 |
|------|-------------|---------------------|-----------|
| 深度 code generation | ✅ Opus, 完整 context | ⚠️ 較淺，repo-level | Claude Code |
| Code review（深度） | ✅ 8-dimension review-code | ⚠️ Agentic review（淺） | Claude Code |
| Issue → auto PR | ❌ 不跑在 GitHub | ✅ 核心能力 | Copilot |
| Branch management | ⚠️ 手動 git 操作 | ✅ 自動 branch + push | Copilot |
| Draft PR creation | ⚠️ 可用 `gh pr create` | ✅ 自動建立 + 持續更新 | Copilot |
| Agentic code review | ❌ | ✅ PR 上自動 review | Copilot |
| Fix PR review comments | ❌ | ✅ 自動產出 fix PR | Copilot |
| Inline completion | ✅ 但不是主要用途 | ✅ 成熟 | Copilot（在 Zed 裡） |
| MCP tool access | ✅ koopa0, Auggie | ❌ | Claude Code |
| Go-spec agents | ✅ comprehend, planner 等 | ❌ | Claude Code |
| 複雜 refactor | ✅ | ⚠️ 簡單任務可以 | Claude Code |
| 安全 review | ✅ security-reviewer | ⚠️ 基礎 | Claude Code |

### 4.2 建議分工

```
開發流程：

1. 規劃階段
   Claude Code: comprehend → planner → 產出 plan
   
2. 實作階段
   Claude Code: 深度實作（Tier 2-3 任務）
   Copilot Coding Agent: 簡單 Issue（Tier 1，bug fix, 明確的小 feature）
     → 在 GitHub Issue 上 assign 給 Copilot
     → 自動建 branch, commit, 開 draft PR
     
3. Review 階段
   Copilot: Agentic code review（第一道 PR review）
   Claude Code: 深度 review-code（第二道，paranoid review）
   
4. Git 操作
   Copilot: Issue → branch → draft PR（自動化 pipeline）
   Claude Code: commit message 品質、verify 前的 lint/test（本機）
   
5. Inline completion（寫 code 時）
   Zed: Copilot 做 edit prediction（日常快速補全）
   Claude Code: 複雜邏輯、需要 context 的 generation
```

### 4.3 Copilot Coding Agent 配置要點

- **啟用**：Repo settings → Copilot → Enable coding agent
- **觸發**：在 GitHub Issue 上 assign `@copilot`，或在 Copilot Chat 要求開 PR
- **安全**：只能 push 到自己建的 branch，不能 approve/merge，PR 需人類 review
- **環境**：跑在 GitHub Actions VM，需要 `copilot-setup-steps.yml` 定義環境
- **監控**：Repo → Agents Tab 管理所有 agent 任務

### 4.4 不需要 Copilot 做的事

- Code completion in IDE — 你可以用，但 Claude Code 的 context-aware generation 更強
- 複雜架構決策 — Copilot 沒有你的 go-spec agents
- 安全審計 — 不夠深入
- MCP 互動 — Copilot 無法存取 koopa0.dev 知識庫

---

## 5. Chrome DevTools 整合

### 5.1 方案比較

| 方案 | 說明 | 需要自己開發 |
|------|------|-------------|
| **Claude Chrome Extension**（官方） | Claude Code bridge：console errors, network, DOM 直送 Claude Code session | 否 |
| **Chrome DevTools MCP** | MCP server 橋接 Chrome DevTools Protocol，Claude Code 可操控瀏覽器 | 否（npm 安裝） |
| **自己開發 Chrome Extension** | 客製化瀏覽器行為 | 是 |

### 5.2 Claude Chrome Extension（官方，建議先用）

- 付費用戶（Pro/Max/Team/Enterprise）可用
- 安裝後自動連接正在跑的 Claude Code session
- 能力：讀 console log/error、監控 network request、檢查 DOM、自動化瀏覽器操作
- **對 koopa0.dev 開發的價值**：前端 Angular SSR debug 時，瀏覽器錯誤直接進 Claude Code context

### 5.3 Chrome DevTools MCP（進階，按需加入）

安裝：

```bash
# Plugin marketplace 方式（推薦）
claude plugin marketplace add ChromeDevTools/chrome-devtools-mcp
claude plugin install chrome-devtools-mcp

# 或 CLI 方式
claude mcp add chrome-devtools npx chrome-devtools-mcp@latest
```

提供的工具：`list_pages`, `select_page`, `navigate_page`, `take_snapshot`, `take_screenshot`, `click`, `fill`, `evaluate_script`

**適用場景**：需要 Claude Code 自動化操作瀏覽器（例如測試 koopa0.dev 前端流程）

### 5.4 建議

**不需要自己開發 Chrome Extension。** 官方 Claude Chrome Extension + Chrome DevTools MCP 已覆蓋大部分需求。如果未來有非常具體的、這兩者無法滿足的瀏覽器端需求，再考慮客製化。

---

## 6. 統一管理 UI 願景設計

> 這是 expansionary engineering，記錄設計供日後實施。不在 production mode 範圍內。

### 6.1 目標

在 koopa0.dev 前端提供 Cowork 專案的統一管理介面：
- 看到所有 Cowork 專案的 schedule 定義和執行狀態
- 拖拉調整 schedule
- 分派任務（建立 directive）
- 看到各專案的 report 和產出
- 觸發 on-demand 執行

### 6.2 架構概念

```
┌────────────────────────────────────────────┐
│           koopa0.dev Dashboard              │
│                                             │
│  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Cowork      │  │ Task Board          │  │
│  │ Projects    │  │ (directives +       │  │
│  │ ├─ HQ       │  │  reports across     │  │
│  │ ├─ Content  │  │  all projects)      │  │
│  │ ├─ Research │  │                     │  │
│  │ └─ Learning │  │                     │  │
│  └─────────────┘  └─────────────────────┘  │
│                                             │
│  ┌──────────────────────────────────────┐   │
│  │ Schedule Manager                      │   │
│  │ (drag & drop, enable/disable,        │   │
│  │  execution history, next run time)   │   │
│  └──────────────────────────────────────┘   │
└────────────────────────────────────────────┘
         │
         ▼ (API)
┌────────────────────────────────────────────┐
│           koopa0.dev Backend                │
│                                             │
│  existing:                                  │
│  - session_notes (directive/report)         │
│  - tasks                                    │
│  - projects                                 │
│                                             │
│  new (future):                              │
│  - cowork_schedules table                   │
│  - cowork_executions table                  │
│  - cowork_projects table                    │
└────────────────────────────────────────────┘
         │
         ▼ (MCP read/write)
┌────────────────────────────────────────────┐
│  Cowork Desktop / Cloud Schedule            │
│  (各 project 的 scheduled tasks)            │
└────────────────────────────────────────────┘
```

### 6.3 實施前提

1. 先用 Cloud Schedule 跑 2-4 週，累積經驗，確定需要什麼 dashboard 功能
2. 確認 Cowork scheduled tasks API 是否可程式化操作（目前只有 UI）
3. 確認實際使用中，哪些 directive → report 流程需要更快的反饋循環

### 6.4 最小可行版

如果要快速驗證，不新增 DB table：
- 利用現有 `session_notes` 做 directive/report 的 timeline view
- 利用現有 `tasks` 做跨 project 的任務看板
- 前端只是把這些現有 API 用 dashboard 形式呈現

---

## 7. 建議行動計劃

### 立即可做（本週，零 engineering）

| # | 行動 | 說明 |
|---|------|------|
| 1 | 修正 `note_type` 不一致 | HQ 用 `"directive"` 但 Content Studio 讀 `"ceo-directive"` — 統一為 `"directive"` |
| 2 | Zed settings 加入 koopa0 MCP | `context_servers` 配置，讓 Zed Agent Panel 可用知識引擎 |
| 3 | Zed settings 加入 Auggie MCP | `auggie --mcp --mcp-auto-workspace` |
| 4 | Zed Copilot 啟用 | Settings → GitHub Copilot Chat → Sign in；edit prediction provider 設為 copilot |
| 5 | 安裝 Claude Chrome Extension | 連接 Claude Code session，前端 debug 用 |

### 本週可做（配置 + 測試）

| # | 行動 | 說明 |
|---|------|------|
| 6 | HQ Cloud Schedule | `claude.ai/code/scheduled` → 每日 08:00 morning briefing |
| 7 | Content Studio Cloud Schedule | 每日 14:00 pipeline check + RSS 監測 |
| 8 | GitHub Copilot Coding Agent 啟用 | Repo settings → enable → 設定 `copilot-setup-steps.yml` |
| 9 | Chrome DevTools MCP 安裝 | `claude mcp add chrome-devtools npx chrome-devtools-mcp@latest` |

### 中期（production mode 結束後）

| # | 行動 | 說明 |
|---|------|------|
| 10 | Dashboard MVP | 用現有 API 做 directive/report timeline + task board |
| 11 | Schedule 管理 | 如果 Cowork API 支援程式化操作，整合到 dashboard |

---

## 8. 待決事項

| # | 問題 | 需要決策的人 | 優先級 |
|---|------|-------------|--------|
| 1 | `note_type` 統一命名：`directive` vs `ceo-directive` — 要用哪個？ | Koopa | P1 |
| 2 | Copilot Coding Agent 適用範圍：所有 Tier 1 issue 都 assign 給 Copilot，還是特定類型？ | Koopa | P2 |
| 3 | Cloud Schedule 是否需要每個 Cowork project 對應一個 scheduled task，還是由 HQ 統一跑？ | Koopa | P1 |
| 4 | Zed 裡 edit prediction 用 Copilot 還是 Zeta？需要試用後決定 | Koopa | P3 |
| 5 | Dashboard MVP 排期 — 等 production mode 哪個階段結束後開始？ | Koopa | P3 |

---

## 9. 資料來源

### Cowork & Scheduled Tasks
- [Get started with Cowork](https://support.claude.com/en/articles/13345190-get-started-with-cowork)
- [Organize your tasks with projects in Cowork](https://support.claude.com/en/articles/14116274-organize-your-tasks-with-projects-in-cowork)
- [Schedule recurring tasks in Cowork](https://support.claude.com/en/articles/13854387-schedule-recurring-tasks-in-cowork)
- [Cloud Scheduled Tasks - Claude Code Docs](https://code.claude.com/docs/en/web-scheduled-tasks)
- [BUG: Cowork scheduled tasks don't fire unless focused (#36131)](https://github.com/anthropics/claude-code/issues/36131)
- [Claude Cowork: Ultimate Autonomous Desktop Guide (2026)](https://o-mega.ai/articles/claude-cowork-the-ultimate-autonomous-desktop-guide-2026)

### GitHub Copilot Coding Agent
- [About GitHub Copilot coding agent - GitHub Docs](https://docs.github.com/en/copilot/concepts/agents/coding-agent/about-coding-agent)
- [From idea to PR: A guide to GitHub Copilot's agentic workflows](https://github.blog/ai-and-ml/github-copilot/from-idea-to-pr-a-guide-to-github-copilots-agentic-workflows/)
- [Asking Copilot to create a pull request](https://docs.github.com/copilot/using-github-copilot/coding-agent/asking-copilot-to-create-a-pull-request)
- [GitHub Copilot coding agent 101](https://github.blog/ai-and-ml/github-copilot/github-copilot-coding-agent-101-getting-started-with-agentic-workflows-on-github/)
- [GitHub Copilot support in Zed GA](https://github.blog/changelog/2026-02-19-github-copilot-support-in-zed-generally-available/)
- [Copilot x Zed — Zed's Blog](https://zed.dev/blog/copilot)

### Zed IDE + MCP
- [MCP in Zed - Official Docs](https://zed.dev/docs/ai/mcp)
- [MCP Server Extensions](https://zed.dev/docs/extensions/mcp-extensions)
- [Zed Edit Prediction Docs](https://zed.dev/docs/ai/edit-prediction)
- [GitHub Copilot - ACP Agent in Zed](https://zed.dev/acp/agent/github-copilot)

### Augment Context Engine
- [Augment Context Engine MCP Overview](https://docs.augmentcode.com/context-services/mcp/overview)
- [Zed Quickstart - Augment Code](https://docs.augmentcode.com/context-services/mcp/quickstart-zed)
- [Auggie CLI — Zed Extension](https://zed.dev/extensions/auggie)
- [Augment Code - ACP Agent in Zed](https://zed.dev/acp/agent/augment-code)

### Chrome DevTools
- [Claude Code Chrome Docs](https://code.claude.com/docs/en/chrome)
- [Chrome DevTools MCP - GitHub](https://github.com/ChromeDevTools/chrome-devtools-mcp)
- [How to Set Up Chrome DevTools MCP for Claude Code](https://samwize.com/2026/03/26/how-to-set-up-chrome-devtools-mcp-for-claude-code/)

### Multi-Agent Frameworks（參考）
- [Agent Teams - Claude Code Docs](https://code.claude.com/docs/en/agent-teams)
- [oh-my-claudecode](https://byteiota.com/oh-my-claudecode-multi-agent-orchestration-for-claude-code/)
