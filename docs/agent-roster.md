# Agent Roster — koopa 的多 agent 模型導讀

> **Status**: outline / skeleton。每節描述應放什麼內容，內容尚未填入。
> 第一版填入內容前請 review 結構。

## 導言

- **給誰讀**：第一次接觸 koopa 的讀者，從 README 看到 HQ / Content
  Studio / Research Lab / Learning Studio 但不清楚這「4 個」是什麼
- **這份 doc 不負責**：完整工具清單（→ `internal/mcp/ops/catalog.go`）、
  schema（→ `migrations/001_initial.up.sql`）、決策政策
  （→ `.claude/rules/mcp-decision-policy.md`）
- **這份 doc 負責**：定義 + 索引 + 為新讀者建立心智模型

---

## §1. 在 koopa 裡，「agent」是什麼

- 一段 gloss：agent 不是 Claude.ai 的訂閱、不是 microservice、不是
  conversation thread；是 `internal/agent/registry.go::BuiltinAgents()`
  的一個 Go literal — 帶 capability bit、可選 schedule、自己的 role prompt
- 引用：每個 MCP call 帶 `as: "<agent_name>"`；server trust + capability
  compile-time gate（`agent.Authorize` wrapper）
- 兩個結構性必備事實先講：
   - capability 是 Go **編譯期** enforced，不是 runtime if-check
   - 詞彙陷阱：「task」≠「todo」；「agent_note」≠「note」；
     「directive」是 tool 名字的隱喻，DB 裡是 `tasks` row（沒有
     discriminator 欄位）

---

## §2. 為什麼是多 agent

- 一段話：多 agent ≠ 多次叫 model API；是把 role + capability +（可選）
  schedule 結構化，讓不同職權邊界 / 不同節奏 / 不同 prompt 各自運作
- Studio 隱喻：HQ 是 CEO，三個是部門
- 三個結構性差異
   - capability bit 不同 → 能做什麼是編譯期決定
   - schedule **可選**（`hq` / `content-studio` / `research-lab` 有 cron；
     `learning-studio` 與其他都 on-demand）
   - role prompt 不同 → 行為紀律不同r
- 不在這份 doc：proposal-first 政策、maturity assessment
  （→ `.claude/rules/mcp-decision-policy.md`）

---

## §3. How agents talk to each other（A2A 一頁概論）

- 三個 channel：`tasks` / `task_messages` / `artifacts`
- `propose → commit → acknowledge → file_report` 流程圖（ASCII）
- 一句話的 capability gate：compile-time wrapper 阻擋未授權 mutation
- 一句話的 directive vocabulary：tool 名字隱喻，row 是 `task`
- 詞彙陷阱重提（task ≠ todo / agent_note ≠ note）
- Link to:
   - `skills/koopa-system/references/a2a.md`（深度版）
   - `.claude/rules/mcp-decision-policy.md` §14（決策政策）

---

## §4. The roster（一張表）

| Name            | Display         | Platform      | Capabilities                  | Schedule     | One-line role | Project Instructions         |
| --------------- | --------------- | ------------- | ----------------------------- | ------------ | ------------- | ---------------------------- |
| hq              | Studio HQ       | claude-cowork | SubmitTasks, PublishArtifacts | `0 8 * * *`  | …             | docs/Koopa-HQ.md             |
| content-studio  | Content Studio  | claude-cowork | Submit, Receive, Publish      | `0 14 * * *` | …             | docs/Koopa-Content-Studio.md |
| research-lab    | Research Lab    | claude-cowork | Submit, Receive, Publish      | `0 9 * * 1`  | …             | docs/Koopa-Research-Lab.md   |
| learning-studio | Learning Studio | claude-cowork | Receive, Publish              | on-demand    | …             | docs/Koopa-Learning.md       |
| koopa0-dev      | koopa           | claude-code   | (dev session)                 | on-demand    | …             | (none)                       |
| go-spec         | go-spec         | claude-code   | (dev session)                 | on-demand    | …             | (none)                       |
| claude          | Claude          | claude-web    | (none)                        | on-demand    | …             | (none)                       |
| human           | Koopa           | human         | SubmitTasks                   | n/a          | …             | n/a                          |
| system          | System          | system        | (none)                        | n/a          | …             | n/a                          |

> **注記**：`koopa0-dev` 顯示為 `koopa`、`human` 顯示為 `Koopa`。
> Audit log 視覺撞名是已知狀態，不是 bug — `name` 欄位才是 actor FK。

---

## §5. Cowork agents — 詳細介紹

每節結構固定（每個 agent 不超過 12 行）：

```
- 一句話定義（≤ 25 字）
- 主要做的事（3 條 bullet）
- 主要不做的事（3 條 bullet）
- 主要互動對象
- Schedule（cron 字串 或 "on-demand"）
- Project Instructions: docs/Koopa-XXX.md
```

### §5.1 Studio HQ

（按上面結構填入）

### §5.2 Content Studio

（同上）

### §5.3 Research Lab

（同上）

### §5.4 Learning Studio

（同上）

---

## §6. Other identities

不在 cowork 跑 / 非業務 agent。每節說明：(a) 它是什麼、(b) 為什麼存在於 registry。

### §6.1 Claude Code dev agents：`koopa0-dev`、`go-spec`

- Claude Code 的 dev session 身份
- 不是業務 agent，但需要 actor FK 來支撐 audit
- 沒有 capability bit（不能 submit / receive / publish via a2a）

### §6.2 General sessions：`claude`

- claude-web 的 read-only 一般對話
- 沒有 mutation 權限

### §6.3 Human：`human`

- Koopa 自己（display: `Koopa`）
- 唯一有 publish content 權限的身份
- 唯一可以 commit 高承諾 entity（goal/project/...）的最終裁決者

### §6.4 System trigger fallback：`system`

- **不是 operational sense 的 agent**
- 只在 `koopa.actor` session var 未設時被 `activity_events` AFTER trigger
  引用 — pg_cron job、手動 psql、Go path 漏設 actor 的 fallback
- 出現在 `activity_events.actor='system'` 是紅旗，代表 Go 路徑漏掉
  actor binding

---

## §7. Security model

- **Single-admin by design**（取自 README §Scope and limits）
- 沒有 RBAC、沒有 multi-tenant
- Capability **是** authority，不是 transport — server 信任 `as` claim、
  capability 驗證走 Go 編譯期 gate（`agent.Authorized` wrapper，外部
  package 無法構造）
- 升級路徑：OAuth identity → agent 映射，已預留但未啟用

---

## §8. Reading order

| 我想…              | 順序                                                                                               |
| ------------------ | -------------------------------------------------------------------------------------------------- |
| 理解 koopa 整體    | README → 本 doc → `docs/backend-semantic-contract.md`                                              |
| 理解某個特定 agent | 本 doc §5.x → `docs/Koopa-XXX.md`                                                                  |
| 加一個新 agent     | 本 doc §9                                                                                          |
| 看完整工具表       | `internal/mcp/ops/catalog.go::All()`（不在本 doc 列工具，因為 catalog 會漂移；catalog.go 是 SSOT） |

---

## §9. How to add a new agent

1. 編輯 `internal/agent/registry.go::BuiltinAgents()` 加一個 `Agent`
   literal（name、display、platform、capability、optional schedule）
2. 啟動時 `SyncToTable` 會把它投影進 `agents` 表
3. 如有新 capability，需要在 Go 編譯期加 authorize 規則
4. 在本 doc §5 / §6 加一節（依是否為業務 agent）
5. 如要新 cowork project，新增 `docs/Koopa-XXX.md`（project instructions）
6. 如要綁 schedule backend，看 `internal/agent/registry.go::Schedule.Backend`

---

## Authority order（footer）

若本 doc 與下列任一矛盾，以下列為準：

1. `migrations/001_initial.up.sql` — schema 是真理
2. `internal/agent/registry.go::BuiltinAgents()` — agent 身份來源
3. `.claude/rules/mcp-decision-policy.md` — 行為政策
4. `docs/Koopa-XXX.md` — agent 自己的 project instructions

本 doc 是讀者導讀，不是 SSOT。
