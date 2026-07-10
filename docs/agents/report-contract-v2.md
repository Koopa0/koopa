# 報告契約 v2 — Cowork 日報/週報的生成規格

> **狀態**：draft（本 repo 只是起草位置；正本應複製進 Cowork planner 的 project
> instructions——Cowork agent 擁有自己的文檔，見 agent ownership 邊界）。
> **對應決策**：work-orders-2026-07.md §1 的 D-A / D-B / 3.4。
> **目的**：報告品質不再取決於 owner 當天給多少上下文。這份契約就是上下文。

## 1. 這份報告是什麼

owner 的**正式 Desk**——全系統 owner 出席率最高的讀取面。它是 agent-authored 的
編輯物，不是 dashboard dump：有 lede、有輕重、有建言、有待決事項。
產出位置：`~/obsidian/System/reports/daily-briefing/latest.html`（覆寫）＋
`archive/YYYY-MM-DD.html`（週報另存 `weekly/YYYY-Www.html`）。

節奏：**日報 = 輕**（資料刷新＋urgent＋≤2 則建言）；**週報 = 深**（完整建言＋
待決清單＋digest 攣生，見 §6）。

## 2. 三段固定輸入（雙平面 + agent 觀察）

| 輸入 | 來源 | 配方 |
|---|---|---|
| 執行平面 | koopa0.dev MCP（`as:"claude"`） | `brief(mode=morning)`、`project_progress`、`review_period(since=7天前)` |
| 知識平面 | vault 檔案系統 | `~/obsidian/System/reports/` 近 7 天新增/更新的報告：檔名＋frontmatter title/status＋一句摘要（hermes 夜巡備料；沒有備料就自己 ls＋讀 frontmatter） |
| agent 觀察 | MCP `brief` 的 `status_notes`（PR-13 落地後啟用；未落地前此區顯示「尚未啟用」） | 近 7 天，新→舊 |

PR-10 落地後追加讀取：`inbox_pending`、`dormant_recurring`、`active_goals[].deadline`。
§5 待決事項區的資料源＝`list_inbox`（PR-5；全量跨 creator）——count 來自 brief、明細來自 list_inbox。

## 3. 版面契約（owner 已認得這個版型，勿大改）

沿用現行結構：masthead → lede → KPI scoreboard → urgent（條件顯示）→
**觀察與建議（insights）** → 分域進度 → 六大領域卡 → 已發布內容 →
全部目標表 → 近期回顧 → **待決事項（新，§5）** → 技術雷達（RSS）→ footer。

**KPI scoreboard 固定行（v2.1，賭注 P 的可觀測面）**：scoreboard 恆含一行
**發布 cadence**——近 28 天 published 數（digest／非 digest 分列）＋距上次 publish
天數；資料源＝`review_period` 或 content 查詢，取不到則標「資料未取得」，不得省略
該行。0 也照實顯示——這一行就是 work-orders §0 賭注 P 的日常讀數。

技術契約（沿用已驗證 pattern）：
- 自足單檔 HTML，`INJECT:SNAPSHOT:START/END` 區塊烘焙當日快照
- Cowork 內開啟時 `window.cowork.callMcpTool` 即時重拉並標示「即時資料」；
  失敗降級「當日快照」——**絕不把陳舊資料標成即時**
- zh-Hant；行動裝置可讀（現有 @media 續用）
- 每個數字必須可追溯到一次 tool response 或烘焙快照；**不得編造或估算數字**；
  某工具失敗 → 該區顯示「資料未取得」

## 4. 建言（insights）準則 — 這是報告的靈魂

1. **上限 4 則**（日報 ≤2）。找不到值得說的就少寫——空建言比湊數誠實
2. 每則必須引用**兩個平面各至少一筆資料**，或明標「單源：僅執行平面」
3. tone 三分類：`warn`（停擺/風險）/ `good`（動能，最多 1 則）/ `info`（方向）
4. 每則以**下一步**收尾：一個具體、今天就能做的動作（可直接建議 owner 在對話裡下裁決）
5. deadline 逼近的 goal **無條件進 urgent 區**（不佔 insights 額度）
6. 不奉承、不填充；引用其他 agent 報告時附檔案路徑（跨 agent 引用必附證據）
7. **上週建言後續**（週報必備段，防模板化退化）：逐條回顧上週每則建言——已行動／被忽略／已過時，
   各一句。連續兩週被忽略的建言不得原樣重複，要嘛換角度要嘛明寫「第三週：owner 已兩次未採，建議正式棄案」

## 5. 待決事項區（D-A/D-B 的報告端）

- PR-5（`triage_todo`）落地後：列出 inbox 全部 items——標題、created_by、age、
  已有的 annotate 註記摘要。排序：age 降冪
- 首階段（D-B a）：區塊底部固定一行提示——
  「在對話中回覆裁決即可執行：如『1,3 dismiss；2 accept 掛 <goal>』」
- 次階段（D-B b）：每筆加〔接受〕〔someday〕〔dismiss〕鈕，
  `callMcpTool("mcp__koopa0-knowledge__triage_todo", {...})`，成功後行內標記已處理。
  按鈕只在 Cowork 環境顯示（`window.cowork` 存在時）

## 6. 週報 = digest 攣生（3.4 的實作）

週日產出時同一次計算出兩份：
1. **週報**（私有，本契約全版面＋完整建言）
2. **digest 草稿**：從 review_period 資料改寫成第一人稱週記體
   → `propose_content(type=digest)` 進 review queue（恆 `is_public=false`）
   → owner 在 admin publish 時逐期決定公開與否
   → **公開版預設排除 移居/身體/文學 area 的內容**（純 prompt 層規則）；
     私域素材以抽象一句帶過或省略
3. digest 草稿末尾附 frontmatter 註記：資料窗（since/until）＋生成日，供回查

## 7. 品質底線與禁區

- 禁：捏造數字、把估計寫成事實、把烘焙快照標成即時、超過 4 則建言、
  引用 vault 內容不附路徑、在公開 digest 洩漏私域細節
- 建言與審計型 session 互為第二意見：兩者分歧 → 在報告中並列兩說並標「待 owner 裁決」，
  不擅自擇一

## 8. 版本

- v2（2026-07-05）：初版契約化。雙平面輸入、建言準則、待決事項區、digest 攣生。
  變更需 owner 同意；修改後同步更新 Cowork planner 內的正本。
- v2.1（2026-07-07，第五輪產品審查）：KPI scoreboard 新增固定「發布 cadence」行
  （近 28 天 published 分列＋距上次 publish 天數，0 照實顯示）——對應
  work-orders-2026-07.md §0 雙賭注中賭注 P 的日常可觀測面。
