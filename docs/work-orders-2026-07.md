# koopa0.dev 工作令 2026-07（審查定案 → 實作追蹤）

> **這份文檔是什麼**：2026-07-05 全面審查（語意 × 測試/CI × 前端 × DB × live 資料 × devil's advocate ×
> 使用者情境）收斂出的**唯一實作追蹤文檔**。owner（Koopa）逐條實作，Claude 驗收；
> 任何新的 Claude session 讀完本檔即可接續指導，不需要原始對話。
>
> **權威順序**：code > migrations > 本檔。本檔記錄「決定了什麼、為什麼、做到哪」；
> 實作細節以 code 為準。發現本檔與 code 衝突 → code 贏，並更新本檔。
>
> **維護規則**：狀態與完成紀錄由 owner 或驗收 session 更新（append 風格，不重寫歷史）；
> 變更日誌每次一行。全部收尾後本檔歸檔（移往 docs/archive/ 或刪除，owner 決定）。

---

## 0. 心智模型 v2 與北極星（所有設計對着這個評估）

**雙平面架構**（join 發生在 agent context window，不做同步、不做 ingestion）：

| 平面 | 系統 | 回答 | agent 取用 |
|---|---|---|---|
| 執行平面 | koopa0.dev（DB+MCP） | 我正在做什麼、承諾了什麼 | MCP tools |
| 知識平面 | ~/obsidian（lifecycle vault，**永不 PARA 化**） | 我知道什麼、研究過什麼 | 檔案系統（agents 都在 Mac 上） |

**北極星**（owner 已認可，待貼進本機 CLAUDE.md — 見 W-7）：

1. agents 是日常使用者；owner 是每週來兩次的總編輯
2. agent 側：寫入 additive/inert、回讀便宜（filters/counts）、完成的工作異步落檔（status note / review queue）
3. owner 側：**控制台是「與 Claude 的對話」＋ agent 產出的報告**，不是 admin、不是 Telegram。admin = 後場工具間（表單/bulk/publish）。新 admin 頁面必須通過「我每月會來嗎」測試
4. 之間：授權在系統內留痕（DB state change + activity_events）；判斷不可預授權；簿記不需要 owner 出席
5. 反面教材（勿重演）：為 4 篇文檔建 hybrid search、為 10 條連結建工業 collector、為 7/35 出席建 47 頁 cockpit——**為觀測到的使用者設計，不為理想使用者設計**

**路由三角**（每個 agent 契約一句話）：actionable → koopa0.dev inbox；knowledge → vault（照 lifecycle 規則）；advice → 報告 insights。不落第四個地方。

**雙賭注與判決矩陣（07-07 第五輪產品向審查）**：本系統對 owner 的耐久價值有兩個候選命題，
同一個 28 天觀察窗（G-1）內並行取證，不先驗擇一：

- **賭注 A（對話控制台）**＝D-A：owner 會在對話＋報告持續裁決。判準＝W-12 ①②③
- **賭注 P（發布引擎）**：系統的耐久產出是「公開站上的作品」——digest／文章／case study
  餵 /hire funnel 與個人品牌；owner 以「每週兩次的總編輯」身份出席即足。
  信號＝窗內 published ≥2 期 digest **或** ≥1 篇非 digest 內容（W-12 判決書同場記錄，
  不影響 A 的 PASS/FAIL 計算）

為什麼要有 P：全隊列修的是輸入／triage 迴路，但 owner 出席的內在動機只可能來自產出
（發布物、客戶線索）——triage 是 chore、報告是唯讀；發布迴路持有全系統唯一的外部硬回報
（/hire 攬客、可引用作品）。若 triage 修通而發布持續為零，修好的系統仍是精緻的鬼城。
供給側配套見 W-13（內容管線接種：素材改寫，不從零寫）。

判決矩陣（W-12 出具）：A✓P✓ → 照 §4 全案續行｜A✗P✓ → 產品重心轉發布引擎：GTD 面
收縮至 inbox+triage 薄層、條件層永久凍結、goals/areas 存廢進下一輪審查｜A✓P✗ →
內容管線復盤（W-13 檢討＋publish 卡點分析）｜A✗P✗ → 系統降維護模式，radical shrink
進下一輪審查。


**hermes ↔ Claude Code 三柵欄**：
1. 各自的家不互寫（hermes 策展 vault、Claude Code 管 repos）；交會點只有 `obsidian/System/reports/`（additive、新報告 supersede 不改舊）與 koopa0.dev inbox
2. actionable 意圖只有一個落點（inbox），不走側信道
3. 跨 agent 引用必附檔案路徑或 koopa0.dev id（evidence or it didn't happen）

---

## 1. 鎖定決策（防止重新翻案；改動需 owner 明示）

| # | 決策 | 為什麼（一句話） | 日期 |
|---|---|---|---|
| D-A | owner 決策場 = 對話（任何 Claude 表面）＋報告；不建 admin Desk 頁 | S4（admin 編輯時段）從未發生；kana 打卡實際走對話；報告是 owner 出席率最高表面 | 07-05 |
| D-B | 授權執行：先「對話代執行」（triage_todo），後「報告內建按鈕」（Cowork callMcpTool） | 記錄的實質 = DB state change + audit event，不是 Angular 點擊 | 07-05 |
| D-C | hermes Telegram 日常 push 停用；降級為鬧鐘專用（deadline 逼近才響）。⚠ 鬧鐘會不會被看見未驗證，第一次真實 deadline 觀察 | owner 幾乎不看 Telegram | 07-05 |
| 3.3 | batch 授權 = 對話裡一次回覆蓋 N 筆（經 D-A 演化，取代原 admin 批次 UI 案）；category 預授權**不做**（判斷不可預授權） | 22 筆塞車的真解 | 07-05 |
| 3.4 | digest 迴路啟動：weekly；propose 恆私有；公開與否 owner publish 時逐期決定；公開版排除移居/身體/文學段（agent prompt 層規則） | 系統「用自己」的最短路徑 + content cadence 地板 | 07-05 |
| 3.5 | goal 濃度：`in_progress` 只留 5（假名精熟、Kotonoha 教材、Go 課綱、客戶交付工作室、ヨルシカ購票）；其餘降 `not_started`（暫緩顯示非否定） | 21 個全 in_progress = 無優先級；brief 信噪比 | 07-05 |
| 3.6 | RSS：砍 per-entry curation UI；unread >60 天 retention 刪除；feed 修剪至 ~10（六 high + Alex Edwards + Angular Blog + Golang Weekly + This Week in Rust；Anthropic/Google Cloud 修 URL 或刪） | 1585 unread / 0 curated（11 天）＝curation 是從未被踩過的路 | 07-05 |
| DA-1 | daily-plan 子系統**立即砍除**（plan_day 工具、daily_plan_items 表、admin Plan 頁、brief reflection mode、Today committed 區） | outcome 路徑從未建成；0/6 follow-through；Today 已 due-based。**07-06 誠實化**（第三方 a 裁定）：review_period 與 reflection 不語意等價——砍除＝**放棄 plan-vs-actual 這個問法**（承諾分母隨 plan 廢除），retrospective 由 review_period 承擔 | 07-05 |
| DA-2 | milestones **凍結＋9/01 判決**：organic（非批次）完成 < 3 → 攤平 goals-only。不是現在動工 | 91 rows、organic 完成 ≈ 0–2；但評估窗未走完、拆除成本高 | 07-05 |
| DA-3 | propose_area/goal/project 三件組**完整保留**（先前「下次收縮時拆」撤回） | 低頻使用一個形狀正確的工具不是錯誤；inert-draft 是北極星原型 | 07-05 |
| DA-7 | migration 慣例翻轉：**001/002 凍結，一律 003+ append-only** | prod DB 存在＋6/25 事故；「pre-production 就地改」前提已過期 | 07-05 |
| — | Option B（無 tool-layer authz；`as`=attribution；transport=邊界）重審後**維持** | 封閉 roster；互冒名=配置錯誤非敵手；token 管理買不到真安全 | 07-05 |
| — | agents 表**保留**（FK 錨 + retired 化石保存）；砍 admin agents profile 頁；platform CHECK 不動 | 它是 Option B 唯一硬防線 | 07-05 |
| — | 留 Angular（Go+templ 路線永久關閉）；leverage 見 PR 隊列 Batch-4 註記 | zoneless+OnPush 100%、成熟度已驗證 | 07-05 |
| — | hybrid search / embeddings：凍結不加碼、不回退。**07-06 修正**：「無害」不成立——CJK 檢索在生產實測失效（B-1，見 PR-19；根因：mcp 容器缺 GEMINI_API_KEY → FTS-only，而 'simple' parser 不分詞 CJK）。凍結維持，但 PR-19 的修復是 bug fix 不算加碼 | 柏拉圖模式實例，但成本已付；補償層在生產缺席是事實錯誤（第三方 review B-1 抓出，主 session 復現確認） | 07-06 |
| — | publish 永遠 admin-only（owner 鐵則）＝唯一固定 admin 觸點；先觀察不預先重設計 | 硬 gate 留在 owner 指定的位置 | 07-05 |
| — | rs 重寫（~/.hermes pylib→rs）與本隊列**零耦合**，owner 明示不管 | — | 07-05 |
| G-1 | **D-A 驗證閘（止損）**：W-5 完成日起 28 天為觀察窗；判準與判決見 W-12。PASS → 解鎖條件層（PR-11/12/13/16）；FAIL → 條件層凍結、D-A 的報告半重審（對話半保留——行為證據已支持）。**07-10 補**（codex B-2：相對窗偵測不到「沒起跑」）：W-5 最遲日 **2026-07-17**——依 owner 07-10 節奏承諾（今明兩天收工第一波＋W-5）自動滿足；逾期則執行閘問題重開、隊列規模重議。**窗開定義（codex GO watch#2）**：觀察窗自「W-5 完成**且** W-1 canonical 版已安裝進 Cowork（含 Q6 和解 cadence）」起算——單一完成邊界，缺 W-1 不開窗 | D-A 是「拓撲問題 vs 需求問題」兩個診斷之一的賭注；DA-2/feed 都有 tripwire，唯獨最大賭注沒有止損（第四輪審查 C1） | 07-07 |

**審查主發現存檔**（詳細證據在原審查對話，關鍵數字防遺忘）：owner active days 7/35；todo 開 40 完成 1；
22 筆 hermes 提案卡 inbox 3 天無人能動；contents 全站 4 篇全 published；feed_entries 1585 unread / 0 其他狀態；
daily_plan 6 rows 0 done；21 goals 全 in_progress 全出自 6/24 claude onboarding；milestones 91/15 done（13 筆兩分鐘內批次）；
`system` actor 1 筆化石事件（agents 表有 4 個 retired row：go-spec / koopa0-dev / system / unknown）；
CJK FTS：中文長句成單一 token（schema comment 已承認、embedding 補償）；DB 13MB 無任何備份。

---

## 2. PR 隊列（編號=ID 不變；執行順序見 §4）

> 每條格式：範圍 → 作法 → 驗收條件。完成後 owner 在「完成紀錄」填：日期 / PR# / 怎麼完成 / 驗收 verdict。
> 通用規則：conventional commits、無 Co-Authored-By、`git add` 指名檔案、
> **correctness 類把回歸測試放獨立 commit**（驗收要做「舊碼必紅」）、migration 一律新檔 append-only。

### PR-0 `docs(ops)` + VPS ops 日（非典型 PR：一個 docs PR + 三個環境動作）
- **範圍**：備份體系、goals 降級、Cloudflare rate rule、診斷包歸檔
- **作法**（07-10 reconciled；E1–E6 已執行，**證據已交 acceptance session，最終 committed-HEAD acceptance pending**）：
  1. ~~`server/scripts/backup-db.sh` 進 repo~~ → **撤銷**（E1）。koopa0dev 的每日備份自始存在於 `Koopa0/server`（`scripts/backup-db-r2.sh`、`scripts/setup-cron.sh:42` 的 cron `0 3 * * *`、本地與 R2 各 7 天保留、`alert-rules.yml:177` 的 Grafana `db-backup-stale` 26h 告警）。owner 於 VPS 實測四探針全綠。本 PR 不新增第二套；備份硬化**登記為 repo-B candidates，NOT scheduled**（見下）。「新開私有桶，勿用公開資產桶 koopa0-dev」的**理由撤銷**（E2，owner dashboard 截圖）——該桶無 custom domain、公用開發 URL 已停用，本來就是私有 ops 桶（`R2_PUBLIC_URL` 為死設定，無 Go/TS code 讀取）
  2. **Restore 演練（必做，已執行 E3）**：異地物件是 `pg_dump | gzip` 的**純 SQL `.sql.gz`**，不是 `-Fc`，所以是 `psql` 不是 `pg_restore`。Mac 上 `docker run pgvector/pgvector:pg17` → `gunzip -c … | psql -v ON_ERROR_STOP=1 --single-transaction`（**兩旗標缺一不可**：沒有它們 psql 語句失敗後仍 exit 0）→ oracle 是 **dump 自身 COPY 行數 vs 還原後 18 表精確 count 逐表 diff**（非抽三張）。**不用 prod 當 oracle**（03:00 dump 與演練間會漂移，是上界非等式）
  3. goals 降級 SQL（已執行 E4）。**交易內 `SET LOCAL koopa.actor='claude'`**（owner 07-10 鎖定），基數與後置條件由 SQL 自行 `RAISE EXCEPTION` fail-closed，不靠人工判讀。不加 `SET LOCAL` → `current_actor()` fallback 到 `'human'`（`001_initial.up.sql:874-888`）。**actor 選擇的效果**：`review_period.goals` 只列 in_progress（`internal/project/query.sql:318`），**無論 actor**，降級後這段都剩 5；`claude` attribution 只避免 human-only 指標（`areas[].activity_count`/`neglected` 於 `query.sql:321-337`、`counts.active_days` 於 `:349-357`）被這 16 筆污染——**不可寫成「review_period 全然不受影響」**。語意參考（**須包在含 `SET LOCAL` 的交易內執行**；fail-closed 正本＝owner 執行 runbook 的 `DO $$…RAISE EXCEPTION` 版）：`… WHERE status='in_progress' AND title NOT IN ('假名精熟','Kotonoha 日文教材擴展','Go 課綱擴展','客戶交付工作室成立','ヨルシカ LIVE TOUR 購票')`
  4. Cloudflare WAF rate rule（已執行 E6，owner 截圖）：`/api/search*` 10 req/10s per IP、Block、**使用中**。dashboard 設定安全——`~/server/infra` 只管 cache/headers 兩個 ruleset phase，rate rule 落在未管理的 `http_ratelimit` phase，`tofu apply` 不會還原
  5. `docs/ops/diag.sql`（自 paste-cache 逐位元組復原，read-only）＋ `docs/ops/backup.md`（≤25 行）；工單原寫的 `diag_out.txt` 實為 `~/server/out.txt`（untracked），依 owner 明示刪除、副本先落 scratchpad
  6. **（07-06 B-2；07-10 事實修正，已執行 E5）**4 個既存 projects 現 `goal_id`/`area_id` 全 null。掛載價值有二，**都不是修 area neglect**：①`goals[].projects_total`（live JOIN）；②**未來**歸因（`audit_todos` 經 `projects.area_id` 解析 area）。**原「造成 area neglect 假陽性」敘述為誤**：`area_neglected` 讀 `activity_events.area_id`（write-time snapshot），back-fill 不改寫歷史、`trg_projects_audit` 只在 `UPDATE OF status` 觸發、掛載零事件（實測 25→25）。owner 鎖定掛法：`go-課綱推進`→`Go 課綱擴展`、`kotonoha-教材內容擴充`→`Kotonoha 日文教材擴展`（area 由 goal 帶出）；`大家的日本語-初級i-伴讀量產-l4-l25` 與 `日語伴讀終審` **只掛 `area_id='日語'`、`goal_id` 明確 NULL**（goal 歸屬待日後釐清）。四筆皆 `updated_at=now()`（`.claude/rules/database.md`）
  7. ~~backup 腳本加 file-age 自檢~~ → **撤銷**。監測缺口登記為 repo-B candidate（未排程）——file-age 與 Grafana `db-backup-stale` 盲區互不包含，不是取捨關係
  8. docs PR 收納：本檔、report-contract-v2.md、`docs/reviews/third-party-review-2026-07-06.md`（保留——獨立審查耐久紀錄）；`docs/hermes-proposals-push-spec.md` **owner 裁定含入本 PR**（並修兩處事實漂移：dangling `brief-proposals-section-spec.md` 引用、`list_todos` wire 3→4 欄）。**staging 紀律**：只 `git add` 指名檔，untracked reviews/設計筆記不掃入
- **repo-B candidates（registered, NOT scheduled；歸屬與排程待 owner 裁決）**：
  1. `DISASTER-RECOVERY.md:116,121` 的 `psql` 補 `-v ON_ERROR_STOP=1 --single-transaction`——**confirmed correctness finding**：中段失敗的 dump 帶旗標 exit=3/tables=0（回滾）、不帶 exit=0/tables=18/triggers=4（`trg_contents_audit` 靜默消失，`m.Up()` 回 `ErrNoChange` 仍記「migrations applied」）。缺該 trigger 失去**未來** content audit events＋W-12 的 propose→publish **latency**；**不失** `review_period.published_content`／`counts.content_published`（`internal/content/query.sql:213-222` 直讀 contents）與 W-12 的 review 佇列數/最老齡。附耐久測試（還原後斷言 triggers=5、tables=18）
  2. R2 bucket lock / versioning——備份 token 同持刪除權（`backup-db-r2.sh:64` 呼 `aws s3 rm`）且與 DB 同機（`~/koopa0.dev/.env`）；token split 縮小 roll 連坐半徑，非刪除爆炸半徑
  3. Grafana 伴生規則 `absent_over_time(koopa_db_backup_last_success_timestamp_seconds{database="koopa0dev"}[2h])`（自身 `noDataState: OK`）；**`{database=...}` matcher 與去抖皆必須**。註：不寫「Grafana 嚴格優於 file-age／off-box」——`DISASTER-RECOVERY.md:24` 的 Grafana→Telegram 故障域是 on-box，兩偵測器盲區互不包含
  4. 外部 dead-man switch（腳本成功時 ping 外部、外部沒聽到時告警）——**沒有 off-box、backup-specific 的 freshness/heartbeat monitor**：Cloudflare→email 涵蓋 VPS/tunnel 整台失效，但不涵蓋 cron/backup job/node-exporter 各自的獨立失效。新候選
- **驗收**（證據已交 acceptance session，最終 committed-HEAD acceptance pending）：異地有今日檔（`aws s3 ls s3://koopa0-dev/backups/koopa0dev-db/`——DB 備份用 aws CLI 非 rclone）；`crontab -l` 有 `0 3 * * *`；演練還原 `exit 0` 且 stderr 空、**18 表精確 count 逐表 = dump 自身 COPY 行數**；brief 剩 5 goals（Claude MCP 自驗）；4 projects 掛載後 `project_progress` 的 `goals[].projects_total` 不再全 0（經 `Go 課綱擴展` 與 `Kotonoha 日文教材擴展`——`goals[]` 只列 in_progress，掛到降級 goal 的 project 不出現）；Cloudflare `/api/search*` rate rule 使用中；docs PR merge
- **完成紀錄**：

### PR-1 `ci: gate deploy on CI green`
- **範圍**：只做一件事——deploy 不再與 CI 並行
- **作法**：deploy job 併入 `.github/workflows/ci.yml`，`needs: [go, integration, lint, sqlc-drift, frontend]` + `if: github.ref == 'refs/heads/main' && github.event_name == 'push'`；刪 `deploy.yml` 獨立觸發
- **驗收**：故意紅一個測試的 branch merge 不觸發 deploy（或 needs 鏈 dry-run 驗證）；正常 merge 部署成功
- **完成紀錄**：

### PR-2 `refactor(daily)!: remove the daily-plan subsystem`（最大的一刀）
- **範圍**：`plan_day` 工具＋catalog（15→14）＋drift test；migration **DROP TABLE daily_plan_items**（down=重建 schema，資料不回）；brief 移除 `mode` 參數/reflection mode/`committed_todos`（Go json 忽略 unknown field → 舊 caller 傳 mode:"morning" 不會壞）；Today aggregate 移除 committed 區；admin Plan 頁＋路由＋nav＋specs 刪除
- **前置**：①hermes 先停用 plan_day / brief(reflection)（見 W-4）——**硬前置**：第三方實測 hermes 於 7/05、7/06 連續兩晨仍在呼叫 plan_day ②**動工前做 mini design pass**（找 Claude）：`internal/daily` 砍後剩什麼、`IsCompletedOn` 語意遷去哪（Today due-based 進度仍需它的語意）——這條有真設計決策，不要直接開砍
- **範圍補充（07-06 和解）**：前端消費者一併清——`gtd.store.ts` 的 plan resource／DailyPlanEntry 型別、Today committed 區的前端與 specs
- **範圍補充（07-07 第四輪）**：repo CLAUDE.md 同步——agent 段工具表 15→14、plan_day 列與相關敘述移除（CLAUDE.md 是每個新 session 的 entry point，漂移成本高）
- **驗收**：build/vet/lint/test 全綠；catalog=14 且 drift test 過；`brief(morning)` 其餘欄位 wire 不變（回歸測試）；cmd/app 對未跑新 migration 的舊 schema 能啟動
- **完成紀錄**：

### PR-3 `docs: correct actor-attribution fossils`
- **範圍**：`cmd/app/routes.go:79,236` 兩處「actor='system' fallback」化石註解改為事實（current_actor() fallback='human'；feeds/feed_entries 無 audit trigger）；`agents.name` 的 COMMENT 刪去不存在的 `assignee / curated_by`；**（07-10 追加）**`internal/agent/agent.go:47-49` 註解提到不存在的 `process_runs.kind='agent_schedule'`（CHECK 只允許 'crawl'）——改為事實（對話層提案發現、verifier 證實）
- **注意**：SQL COMMENT 是 sqlc 輸入 → `sqlc generate` ＋ commit `internal/db`
- **驗收**：sqlc-drift CI 綠；grep 無 system-fallback 敘述
- **完成紀錄**：

### PR-4 `feat(mcp): reject non-active caller identity`
- **範圍**：`withActorTx` 加 registry `status==active` 檢查（in-memory，fail-loud）；`server.go:413,420`、`brief.go:84` 範例 `koopa0-dev`（retired！）改 `e.g. claude`
- **驗收**：`as:"system"` / `as:"koopa0-dev"` 被拒（明確錯誤訊息）；四個 active 名通過；測試獨立 commit 舊碼必紅
- **完成紀錄**：

### PR-5 `feat(mcp): triage loop — list_inbox + triage_todo`（D-A/D-B 的落地；07-06 和解擴充）
- **範圍**：兩個新 MCP 工具（catalog +2）：
  ①`list_inbox`（read-only）：**全量** state=inbox rows 不限 creator——id/title/created_by/age_days/description（含
  annotate 註記）。它是 owner triage 佇列的讀取面（修第三方 I-1：W-5 清倉與報告契約 §5 原本無資料源，
  list_todos 是 caller-scoped 讀不到 hermes 的 22 筆）
  ②`triage_todo`（destructive）：輸入 `{id, verdict, project?, due?, energy?}`；verdict ∈ `accept`（inbox→todo，
  可帶 project/due/energy）| `someday`（inbox→someday）| `dismiss`（inbox→dismissed）| `restore`
  （dismissed|someday→inbox，誤裁回復路徑，第三方 b 裁定補）。accept/someday/dismiss **只作用於 state=inbox**；
  不限 creator（它執行的是 owner 裁決，不是 caller 自清）
- **安全模型**（與 propose_* 同款，寫進工具 description）：只在 owner-present 對話呼叫、絕不排程；audit trail 每筆留痕；hermes 契約明文禁用（兩個工具都是）
- **驗收**：四 verdict＋list_inbox 各有測試；非法 state 轉換回 invalid-state；catalog+drift 同步；audit event actor 正確
- **完成紀錄**：

### PR-6 `feat(db): audit recurring occurrence completions`
- **範圍**：migration（append-only）：`CREATE OR REPLACE FUNCTION audit_todos()` 加分支——`last_completed_on IS DISTINCT FROM OLD.last_completed_on` 時寫 `completed` 事件，payload `{"occurrence":true}`；`review_period` 對 occurrence **聚合顯示**（`早上背幾個日文單字 ×6`），不逐日刷屏
- **為什麼**：habit 完成目前對 momentum/review 全隱形，且 `last_completed_on` 是覆寫欄位——沒有這個 trigger，habit 歷史根本不存在
- **驗收**：打卡→事件存在、actor 正確（owner 在對話裡說「背了」由 claude 代蓋 → actor=claude，語意正確：human-actor-only 統計不計 agent 蓋章——**這是對的**，因為 review_period 的 occurrence 區塊獨立呈現，不混入 human momentum）；cmd/app 對舊 schema 能啟動；review_period 聚合測試
- **完成紀錄**：

### PR-7 `feat(frontend): CSP + server.ts tests`
- **範圍**：`server.ts` 加 CSP（script-src nonce 走 Angular `ngCspNonce`；style-src 先 `'self' 'unsafe-inline'`）；escapeXml/sitemap/RSS/BFF proxy 純 Node 單測（XML escape 是 injection 面）
- **驗收**：公開站零 CSP violation、theme 無 FOUC；`frontend/.claude/rules/security.md:44` checklist 可勾
- **完成紀錄**：

### PR-8 `ci: full-stack gates`
- **範圍**：frontend job 加 `npm test`（headless；89 specs 首次進 CI）＋ Playwright 獨立 job；Go unit lane `-coverprofile` + summary（先不設 floor）；`govulncheck ./...` job；`.github/dependabot.yml`（gomod/npm/actions）；gitleaks job
- **範圍補充（07-06 和解，第三方 i）**：①**docker build job**——三個 image（Dockerfile / Dockerfile.mcp / frontend）在 CI 建置，現況是壞 Dockerfile 只會在 deploy 當下才發現 ②linter 補：gci、bodyclose、noctx、depguard 規則擴充 ③`go test -shuffle=on`
- **驗收**：全綠；coverage 數字出現在 CI log；三個 image CI 可建
- **完成紀錄**：

### PR-9 `test(cmd/mcp): config parsing`
- **範圍**：比照 `cmd/app/config_test.go` 表驅（cmd/mcp 目前 0 測試）
- **驗收**：錯誤 env 各案有斷言
- **完成紀錄**：

### PR-10 `feat(mcp): brief adds inbox_pending / dormant_recurring / goal deadlines`
- **範圍**：morning 加 `inbox_pending`(int)、`dormant_recurring`(int，inbox 且帶 recurrence)；`active_goals` rows 帶出 `deadline`（欄位已存在，wire 缺）；catalog+drift 同步
- **為什麼**：28 筆積壓對所有表面隱形；兩個 habit 沉睡 11 天無人知；會過期的承諾（ヨルシカ票窗）無自動浮出機制。報告（W-1）的資料源就是 brief
- **驗收**：計數正確（以當時 DB 為準）；deadline 有值時出現在 wire
- **完成紀錄**：

### PR-11 `feat(mcp): annotate_todo` — 裁決前的異步備料
- **範圍**：新工具（additive）。對 **state=inbox** 的任意 row **append** 註記到 description：自動加署名行 `\n\n---\n[<caller> <date>] <note>`；**append-only、不可改不可刪原文、cross-creator 允許**（claude 驗證 hermes 提案正是主場景）；可另 set project/due/energy 於**自建**的 inbox row（cross-creator 只能 append 註記）
- **層級（07-07）**：**條件層**——G-1 閘（W-12）PASS 後才動工。主場景（驗證 22 筆 hermes 提案）是一次性事件，清倉後的穩態需求待觀察窗證明
- **驗收**：署名格式測試；cross-creator append 成功、cross-creator 改欄位被拒；非 inbox 被拒
- **完成紀錄**：

### PR-12 `feat(mcp): list_todos filters`
- **範圍**：`state` / `created_by` / `since`（timestamp）三個可選參數（feature-request F3 原案）
- **層級（07-07）**：**條件層**——G-1 閘 PASS 後才動工。W-5 的跨 creator 讀取需求已由 PR-5 list_inbox 覆蓋；filters 服務的是尚未證明的穩態流量
- **驗收**：各 filter 與組合的表驅測試；無 filter 行為不變
- **完成紀錄**：

### PR-13 `feat(mcp): post_status_note` — 完工異步回報
- **範圍**：新小表 `agent_notes(id, body ≤500, created_by FK, created_at)`（migration append-only）；工具（additive）；brief morning 加 `status_notes`（近 7 天、新→舊、cap 20）
- **層級（07-07）**：**條件層**——G-1 閘 PASS 後才動工。**具名提前條款**：觀察窗內若報告/digest 明顯飢餓（status notes 缺席致 agent 完成工作持續隱形，且有具體事例），owner 可單獨提前本 PR，不算翻案——比默默復活整個條件層誠實
- **為什麼**：「/hire 做完了但 todo 躺 inbox」的解——工作完成能在 owner 缺席時落檔，報告 insights 的第三資料源
- **驗收**：長度/控制字元驗證比照 capture_inbox；brief 帶出；catalog+drift
- **完成紀錄**：

### PR-14 `chore(admin): IA trim`
- **範圍**（Desk 已移往報告，本 PR 只剩收斂）：Input group 併入 Knowledge（Feeds 移過去）；`system/agents/:name` profile 頁砍除（list 留）；nav 對應更新
- **驗收**：nav 4 組；路由/specs 綠；**手機驗一次 Today 打卡 ≤2 tap**（不達標開小修單，不擴 scope）
- **完成紀錄**：

### PR-15 `chore(feed): retention + remove triage UI`
- **範圍**：scheduler 加每日清理（`DELETE feed_entries WHERE status='unread' AND collected_at < now()-'60 days'`）；feed-entries triage 頁＋路由＋curate/ignore handler 刪除（entries 照收、highlights 照跑、`curated_content_id` 欄位留）；`feed_entries` 表 COMMENT 誠實化（lifecycle unused since 2026-07）＋ sqlc regen；feed 清單修剪照 3.6（admin 或 SQL 皆可）
- **驗收**：刪後全綠；highlights 照常；retention 有測試（或手動驗一筆過期刪除）
- **完成紀錄**：

### PR-16（可選）`feat(mcp): propose_project goal/cadence params`
- **範圍**：propose_project 加 optional `goal` / `expected_cadence`；admin project 表單 nudge（不強制）
- **跳過條件**：projects 若到執行時仍持續閒置 → 永久跳過
- **層級（07-07）**：**條件層**——G-1 閘 PASS 後才動工；原跳過條件不變（兩者疊加：閘過且 projects 有活動才做）
- **驗收**：帶 goal/cadence 與不帶皆可建（表驅測試）；goal 以 slug/title 解析、解析失敗不阻建案；catalog+drift 同步
- **完成紀錄**：

### PR-17 `chore: deadcode + test-org sweep`（2026-07-06 追加，Zed/Google 級嚴謹度對齊）
- **時機**：**PR-2 與 PR-15 之後**（兩刀的殘渣要一起掃）
- **範圍**：①`golang.org/x/tools/cmd/deadcode ./...` + staticcheck unused 全掃，逐項按 zero-ref 規則分類：
  刪除 / keep-and-wire（背着 live endpoint 的休眠 infra 不是刪除清單）/ 豁免（WithTx 類統一契約）；
  產品語意類候選（series_id/series_order、todos.priority 等「欄位存在但無寫入面」）**只分類不擅刪**，列單給 owner
  ②整合測試組織：`internal/mcp` 的 94KB integration_test.go + 第二個 integration 檔——拆分或在 testing.md 明文化豁免；
  `internal/goal`（~57K）與 `internal/todo`（~42K）的大檔一併檢視（第三方 i 點名）
  ③integration 測試 15 處 `context.Background()` → `t.Context()`（TestMain 內的合法者除外）
  ④`internal/url` 遮蔽 stdlib 套件名——改名（如 urlnorm；第三方 i）
  ⑤**明確排除**：schema vestigial 欄位（series_id/priority 等）是產品語意題，只列單不動（見①的分類規則）
- **驗收**：deadcode 工具零輸出（或每筆殘留附豁免理由）；全 gate 綠；產品語意候選清單交 owner
- **完成紀錄**：

### PR-18 `refactor(mcp)!: rename search_knowledge → search_content + pin visibility`（2026-07-06 追加）
- **為什麼**：雙平面模型下「knowledge」無歧義指 vault；此工具搜的是 contents 發布層——名字說謊。
  改名後歸隊 content 工具家族（propose/list/revise_content）
- **範圍**：catalog+server+search.go+測試（~10 Go 檔）＋ docs/skills 4 檔；
  **visibility 語意用測試釘住**（現狀=搜全部非 archived 含 draft/review，`query.sql` InternalSearchContents）——
  維持或收成 published-only 由 owner 定（傾向維持＋description 明說）；description 同步改寫
- **時機**：**W-2（Cowork instructions）安裝之前**——prompt 只寫一次新名字
- **範圍補充（07-06 和解，第三方 h）**：結果 wire 加 `status` 與 `is_public`——caller 拿到 draft 卻無從得知是 draft，
  「未發佈內容不外引」的規則無法執行；真正的洩漏向量是下游再發佈，不是讀取本身
- **範圍補充（07-07 第四輪）**：repo CLAUDE.md 同步——`search_knowledge` 全部出現處改 `search_content`
  （工具表、invariant 列、reading order），與 PR-2 的 CLAUDE.md 同步同理：entry point 漂移成本高
- **驗收**：drift test 過；舊名 grep 歸零（除本檔與歷史 docs）；visibility 測試存在且對應 owner 裁決；wire 含 status/is_public
- **完成紀錄**：

### PR-19 `fix(search): CJK retrieval integrity`（07-06 和解新增，第三方 B-1——唯一推翻鎖定事實的發現）
- **事實**（主 session 復現）：`search_knowledge("成本意識")` 0 筆，語料裡就有同名標題的已發佈文章；
  `search_knowledge("成本")` 命中的是另一篇（body 恰有孤立 token）。根因兩層：
  ① 'simple' parser 不分詞 CJK（已知）②補償層在生產缺席——**docker-compose 的 mcp service 沒有
  GEMINI_API_KEY**（backend 有），search_knowledge 一直 FTS-only。公開站 /api/search 走 Store.Search 純 FTS，同樣失效
- **19a（一行修，隨時可上）**：compose 給 mcp service 加 `GEMINI_API_KEY: ${GEMINI_API_KEY}` → 部署後
  live 驗證 CJK query 經 semantic 分支命中（CI 無法測 Gemini，驗收=部署後實測 + 「embedder wired」啟動 log）
- **19b（owner 已拍板＝甲，07-06）`refactor(content)!: remove public search surface`**（獨立 PR）：
  砍公開站 search——①前端：`/search` 頁面元件＋specs、`app.routes.ts` 與 `app.routes.server.ts` 的 search 路由；
  grep `routerLink` / `navigate` 到 `/search` 的殘留入口一併清 ②後端：`GET /api/search`（`PublicSearch`
  handler，`internal/content/public.go`）＋ `cmd/app/routes.go` 對應路由；`Store.Search` 依 zero-ref 規則處置
  （先 grep——若 admin global search 的 content Source 也用它則留，否則刪）③Cloudflare `/api/search*`
  rate rule 移除或改指其他路徑（PR-0 期間先留着——endpoint 未砍前保護仍正確）
  **明確不砍**：admin `/admin/knowledge/search`（`internal/search` 背着 live admin 頁，keep）；
  公開站 related-articles（SimilarContents，embedding 路徑，不是 search）；MCP search 工具（PR-18 改名後保留）
- **時機**：PR-17（deadcode sweep）**之前**，殘渣讓 17 一起掃
- **附帶**：§1 hybrid 凍結列已修正；`contents.search_vector` 的 COMMENT「embedding compensates」在 19a 後
  對 agent 路徑成立、對公開路徑則因 19b 砍除而不再適用——COMMENT 補一句限定（sqlc regen 同 PR）
- **驗收**：全 gate 綠；公開站無 search 入口與路由；`/api/search` 回 404；admin search 照常；related-articles 照常
- **完成紀錄**：

---

## 3. W 隊列（非 code 工作項）

| # | 項目 | 誰做 | 內容 / 驗收 | 完成紀錄 |
|---|---|---|---|---|
| W-1 | **報告契約 v2** | Claude 起草 → owner 安裝進 Cowork planner | 草稿在 `docs/agents/report-contract-v2.md`（本 repo 為 draft 位置；正本歸 Cowork project——agent ownership 邊界）。三段輸入（MCP live / vault 近 7 天報告 / status notes）＋建言準則＋週報=digest 攣生。**增補（07-07 第四輪，供 W-12 判準③）**：週報固定「建言後續」段——上期建言逐條列「已回應/未回應」狀態行，讓 owner 是否在讀報告變成可觀測事實，而非只能事後考古。**增補（07-10）**：安裝版須含 Q6 和解後 cadence——日刷 latest.html、耐久歸檔僅週報與實際 check-in（owner 安裝時終裁）；repo 草稿的「日報歸檔」敘述（report-contract-v2.md:12）定稿時同步修正 | |
| W-2 | Cowork planner instructions 更新 | Claude 起草 → owner 安裝 | 含 W-1 契約引用、MCP 配方（含新工具）、vault 檢索地圖引用 | |
| W-3 | vault 檢索地圖 | Claude 起草 → owner 放 `obsidian/System/agent-guides/vault-retrieval.md` | 五個 canonical retrieval questions → Views/MOC/rg pattern 對照；一頁 | |
| W-4 | **hermes 協調**（PR-2 前置） | owner 在 hermes repo | ①停呼叫 plan_day / brief(reflection) ②Telegram 日常 push 停、鬧鐘規則（僅 deadline 逼近）③夜巡輸出改「報告資料包＋inbox captures」④明文禁用 triage_todo ⑤hermes-proposals-push-spec.md 對應更新 | |
| W-5 | **第一次對話清倉**（PR-5 後立刻） | owner+Claude 對話 | playbook：Claude 用 `list_inbox` 拉全量（07-06 修 I-1：資料源就位）→ 列 28 筆＋逐筆 verdict 建議 → owner 回裁決 → triage_todo 執行 → 口頭總結。**注意**：兩個沉睡 habit（二人称精讀、寫心得）accept 時一併喚醒；22 筆裡的內容生產提案（第一篇真實技術文章、工作室 case study）優先裁 | |
| W-6 | **第一次 digest 運行（校準運行，07-07 提前）** | Cowork/hermes 產草稿 → owner | **時機改為 W-5 後第一個週日**——解除 W-1/PR-13 硬依賴（現有 read-only 工具 review_period + propose_content 已足以跑通 propose → owner review → publish 全鏈）。第一次定位為**校準運行**：目的是驗證輸出迴路能走通並給 owner 第一份實際產出，格式不完美可接受；W-1 契約與 PR-13 status_notes 落地後的下一期再升級為正式格式。運行卡點（如 owner 未進 admin publish）不算失敗——記入 W-12 判決材料 | |
| W-7 | 北極星貼進本機 CLAUDE.md（§0 那五條＋路由三角） | owner | 本機編輯（CLAUDE.md gitignored）；同時在 CLAUDE.md 加一行指向本檔 | |
| W-8 | **9/01 milestones 判決** | Claude 拉資料出判決書 | **判準 07-06 釘死**（第三方 d 要求操作化）：窗＝2026-07-06 → 2026-09-01；organic＝該筆完成**不在**任何「同 actor 15 分鐘內 ≥3 筆完成」的批次窗內；organic 完成 <3 → 攤平 goals-only（結構進 goal.description checklist，milestone_done/total 欄位全移除）；≥3 → 保留再觀察一季 | |
| W-9 | ヨルシカ購票處置（本週） | owner | 查場次/票窗 → 推進 milestone-1 或明確棄追（abandoned）。這是全系統唯一會過期作廢的 goal。**兼作 D-C 鬧鐘通道的 live 試驗**（第三方 ⑦）：讓 hermes 對這個 deadline 發一次 Telegram 鬧鐘，驗證「owner 看得見緊急通道」——失效則鬧鐘遷報告置頂 | |
| W-10 | docs disposition 與衛生（07-06 追加） | owner+Claude | ①claude-mcp-feature-requests.md 逐項補 disposition（F1→annotate_todo 改形、F2→拒/triage_todo 取代、F3→PR-12、F4→過時已修、F5→拒（判斷不可預授權）、F6→PR-13）②本檔與 reviews/ 的歸檔政策：全部收尾後移 docs/archive/ ③明拒清單存檔：CONTRIBUTING/CODEOWNERS/issue templates/CodeQL(private=付費)/commit-lint CI/license-header bot——單人 closed repo 的劇場，不做 ④**（07-07 第四輪）repo CLAUDE.md 定位句雙平面化**：開頭「這不是一個部落格…」段落與「平台三大面向」改寫為執行平面（agent 語境）/發布平面（公開站）雙平面敘述，與本檔 §0 對齊 | |
| W-11 | GitHub branch protection（07-06 追加） | owner | main：require CI green（PR-1 的 job）+ block force-push + require PR。設定頁勾選，零 code | |
| W-12 | **D-A 驗證閘判決**（G-1，07-07 追加） | Claude 拉資料出判決書 | 窗＝W-5 完成日 → +28 天。**判準現在釘死**（窗開前 owner 可調數字，窗開後不再議）：①對話 triage 存活：窗內 `triage_todo` 事件（排除 W-5 清倉當日）散佈 ≥4 個不同日；②inbox 不再堆積：窗末 state=inbox 且 age>14 天者 ≤3 筆；③報告出席：窗內週報「建言後續」段獲 owner 回應 ≥2 次（資料源＝報告鏈自身＋W-6 publish 事實，見 W-1 增補）。**三取二＝PASS** → 解鎖條件層；FAIL → 條件層凍結，D-A 報告半重審（屆時選項：報告改址/降頻/裁決回 admin batch；對話半保留）。**判決書同場記錄賭注 P 信號**（窗內 published 計數，判準見 §0）與判決矩陣結論——P 不影響 ①②③ 的 PASS/FAIL 計算，只決定矩陣走向。資料源＝activity_events＋報告存檔，Claude 可自拉。**07-10 增補**（codex B-3/B-5）：①W-1 完整版已提前至 W-5 同步安裝——判準③儀器自窗開就位，三判準觀察期等長；②判決書固定記錄三個發布階段數：review 佇列數、最老 review 齡、propose→publish 延遲——P 失敗可歸因「供給側 vs publish 卡點」，服務矩陣 A✓P✗ 分支的卡點分析。**資料源（07-10 二稿修正，codex 覆核抓錯、verifier 證實）**：latency 與進入 review 時刻取 activity_events 的 contents 審計事件（同 entity 最早進 review 事件 → `published` 的 occurred_at 差；**事件選擇（codex GO watch#1，trigger 原文驗證）**：propose_content 直接以 review 建立——首次進 review＝`created` 事件 payload.status='review'；`to:'review'` 是 revision 後重進，只用它會漏掉初次提案、高估 latency）；佇列數／最老齡取 contents 現況 review 列。原記 brief content_pipeline 不可行——無 published 列、20 筆截斷、updated_at 受一般編輯污染。W-6 校準運行先排練三個數的算法 | |
| W-13 | **內容管線接種**（07-07 第五輪追加，賭注 P 的供給側） | owner＋Claude Code sessions | 零後端 code、純 prompt/skill 層：①W-5 清倉時 inbox 既有兩筆內容生產提案（第一篇真實技術文章、工作室 case study）優先 accept 並各掛 due——它們是 /hire funnel 的第一批彈藥（funnel 現況：/hire 已上線攬客、全站 4 篇、0 case study）②Claude Code dev session 收尾例行化 `/build-log`（skill 已存在、未例行化）——素材自動累積，digest／case study 從素材**改寫**而非從零寫，把內容生產成本砍到 owner 實際會付的量級 ③case study 用現有 build-log/article 型別，**不加新 content type** ④驗收＝窗內 ≥1 篇非 digest 內容走完 propose→review→publish（同時就是賭注 P 的信號源之一） | |

---

## 4. 執行政策（07-07 第四輪修訂——本節為權威，07-06 原順序降為歷史對照）

第四輪審查的核心裁定：**工單個體幾乎全對，錯在把 31 項當無條件整體執行**。
PR-0 標「今天」兩日未動＝執行容量的 live 證據。修訂為兩層政策：

### 4a. 無條件核心（無論 G-1 結果都該做）

```
第一波（本週）：PR-0 → PR-1（＋W-11 隨手設）→ PR-19a → PR-5 → W-5（清倉!）→ W-1（完整版，07-10 提前——判準③儀器窗開就位）
並行（零依賴，不佔隊列位）：W-7、W-9、W-13（②/build-log 例行化即日起；①兩筆內容提案隨 W-5 清倉處理）
第二波（W-5 後）：W-6（校準運行，第一個週日）→ W-4 → PR-2 → PR-3 → PR-4 → PR-10
第三波（穩態整備）：PR-18 → W-2/W-3 → PR-6 → PR-7 → PR-8 → PR-9
→ PR-14 → PR-15 → PR-19b → PR-17 → W-10
```

核心層的判斷標準：修 bug／擋風險（PR-0/1/19a）、直接服務清倉與輸出迴路（PR-5/W-5/W-6/W-13）、
砍確認的死系統（PR-2 及其前置 W-4）、事實修正與衛生（PR-3/4/10/17/18、W-10）、
公開站已拍板收斂（PR-15/19b）。這些不賭 D-A 成敗——D-A 失敗它們也都對
（W-13 服務的是賭注 P，與 A 的成敗獨立）。

### 4b. 條件層（G-1 閘 PASS 後才動工）

```
G-1 判決（W-12，W-5+28 天）PASS → PR-13 → PR-11 → PR-12 → PR-16（仍可選）
```

這四項共同點：服務「對話 triage / 異步備料 / 異步回報」的**穩態流量**，而穩態流量
是否存在正是 G-1 要驗證的命題。閘 FAIL 則凍結，不默默復活（PR-13 有具名提前條款，見工單）。

### 4c. 固定時點項

W-8（9/01 milestones 判決）、W-12（G-1 判決，W-5+28 天）——到期執行，不佔隊列位。

理由：CI gate 先護場 → triage 工具最快讓系統開始為 owner 工作 → 清倉給全隊列第一個真實勝利 →
W-6 提前讓輸出迴路最早見產出 → hermes 協調完才動大刀（PR-2）→ 其餘按風險與依賴。
PR-8 附註：coverage floor 第二階段——baseline 數字出現後訂（觀測值 −2%），不先驗猜。

<details>
<summary>07-06 原建議順序（歷史對照，已被 4a-4c 取代）</summary>

```
PR-0（今天）→ PR-1 → PR-5 → W-5（清倉!）→ W-4 → PR-2 → PR-3 → PR-4
→ PR-10 → PR-13 → W-1 → W-2/W-3 → PR-11 → PR-12 → PR-6
→ PR-7 → PR-8 → PR-9 → PR-14 → PR-15 → W-6 → PR-16（可選）→ W-8（9/01）
```

07-06 追加項的插入位置：PR-18 排在 W-2 之前（prompt 只寫一次新名）；PR-17 排在 PR-15 之後
（兩刀殘渣一起掃）；W-10 隨 PR-13 後的 docs 輪；W-11 隨 PR-1 落地即設。
PR-19a 隨時可上，建議 PR-1 後立即；19b 排在 PR-15 之後、PR-17 之前。
W-7/W-9 零依賴——與 PR-0 同日並行。

</details>

**Batch-4（前端 leverage，全隊列後、改 admin 時順路）**：optimistic UI on `gtd.store.mutate()` →
鍵盤 triage 擴散（review-queue）→ 364 個任意字級收進 @theme type scale → `@defer` island 化重元件 →
admin named View Transitions → `setTimeout(0)`→`afterNextRender`。

---

## 5. 驗收協議（每條 PR 完成後）

1. owner push branch → 告知 Claude session（本檔在手的任何 session）
2. Claude 派 **fresh-context verifier** subagent：驗 **committed HEAD**（非 working tree）；
   跑 `go build ./... && go vet ./... && golangci-lint run ./... && go test ./...`（+integration 視情況）；
   逐條對照本檔該 PR 的驗收條件給 PASS / FAIL / CANNOT-VERIFY 附證據
3. **correctness 類**（PR-2/4/5/6/11 等）加驗「舊碼必紅」：把回歸測試 commit cherry-pick 到 base 上跑，必須紅
4. 實作 session 不自證（adversarial-review 規則）；驗收報告含 stop report 六要素
5. PASS → owner 發 PR merge → 更新本檔「完成紀錄」（日期 / PR# / 一句話怎麼完成 / verdict）

## 6. 新 session 接手協議

1. 讀本檔（你正在做）→ 讀 §1 鎖定決策（**不重新翻案**，除非 owner 明示）
2. `git log --oneline -15` ＋ 掃 §2/§3 完成紀錄 → 找到第一個未完成項
3. 若在驗收：照 §5。若在指導：給該項的具體開工指導（本檔範圍+作法+驗收已足夠展開）
4. code 與本檔衝突 → code 贏，更新本檔並在 §8 記一行
5. 產品語意的新問題 → 問 owner，不自行決定（一如既往）

## 7. 已知風險與觀察點

- `triage_todo`/`annotate_todo` 的 owner-present 規則是 prose 不是硬 gate（Option B 一貫姿態）——audit trail 記錄 actor 與動作，但單一事件無法區分對話 vs 排程呼叫（無 invocation-context 欄位；owner 07-10 裁決：接受不可觀測、不加記錄機制），異常靠時間模式事後研判（codex B-4）
- publish 是唯一固定 admin 觸點：若它成為新瓶頸（digest 週週卡 publish），屆時再議，不預先設計
- D-C 的「Telegram 鬧鐘」未驗證會被看見：第一次真實 deadline 觀察，失效則鬧鐘也遷報告置頂
- PR-2 的 `internal/daily` 收縮需 mini design pass（IsCompletedOn 去向）——已寫進 PR-2 前置
- feed_entries 60 天 retention 後，若 highlights 也長期無人引用 → 下一輪審查考慮整個 feed 子系統的存廢
- 條件層凍結（G-1 FAIL 時）的代價：F1/F3/F6 型 agent 摩擦（claude-mcp-feature-requests.md 存檔）持續存在且不會自動消失——屆時需另擇解法，不是默默復活條件層
- W-6 校準運行會第一次真實撞上 publish 卡點（owner 必須進 admin）——卡住不是失敗，是 D-A 報告半的資料點，記入 W-12 判決材料
- PARA 表面（goals/areas 層級本身）的存廢不在本輪議程：掛 W-8（9/01 milestones 判決）與 W-12（雙賭注矩陣）之後的下一輪審查——兩個判決都出來前不動結構

## 8. 變更日誌

- 2026-07-05：初版。全面審查收斂；D-A/B/C 定案；16 PR + 9 W 項凍結。（Claude／審查 session）
- 2026-07-06：owner 對齊兩點 → 追加 PR-17（deadcode+test-org sweep）、PR-18（search_knowledge→search_content
  改名＋visibility 釘住；工具本身確認保留——遠端 agent 唯一檢索窗口）、W-10（docs disposition＋明拒劇場清單）、
  W-11（branch protection）。嚴謹度基準=Zed/Google 級工程紀律，明拒社群儀式。
  ⚠ 以上標 pending-reconciliation：第三方 fable review 進行中，和解輪一併定稿。（Claude／審查 session）
- 2026-07-06（和解輪，pending 解除——全隊列定稿）：第三方 review（docs/reviews/third-party-review-2026-07-06.md，
  總判決「帶修正照做」）十條修正全數採納，關鍵三條主 session 親手復現後接受：
  **B-1** CJK 檢索生產失效（根因含 mcp 容器缺 GEMINI_API_KEY）→ 新增 PR-19、§1 hybrid 列修正——這是唯一
  推翻鎖定事實的發現；**I-1** W-5 缺跨 creator 讀取面 → PR-5 擴充 list_inbox；**B-2** projects 全無 goal/area
  掛載致 neglect 假陽性（6/29–7/06 六 area 全誤報，已復現）→ PR-0 追加掛載項。其餘：DA-1 理由句誠實化、
  PR-2 硬前置＋前端範圍、triage_todo 加 restore、W-8 判準操作化、W-9 兼鬧鐘試驗、PR-8 加六件 gate、
  PR-17 加 url 改名等、PR-18 wire 加 status/is_public、報告契約加建言後續段。
  待 owner 拍板僅餘：**19b 公開 search 處置**（甲砍/乙標註/丙加碼——推薦甲或乙）。（Claude／和解 session）
- 2026-07-06（終稿）：owner 拍板 **19b＝甲**（砍公開 search surface，工單已寫死範圍與不砍清單）。
  全隊列零 pending：**20 個 PR 工單（PR-0 至 PR-19；16 可選；19 含 a/b 兩個子 PR）＋ 11 個 W 項**。
  fresh-context verifier 驗收本檔：首輪 5/7 PASS，2 FAIL（PR-16 缺驗收、§4 漏 W-7/W-9 位置）＋
  PR 計數算術錯，三者已修正。本檔進入執行期——之後的變更只該是完成紀錄、驗收 verdict、
  與 code-wins 修正。（Claude／和解 session）
- 2026-07-07（第四輪修訂——執行政策）：第四道獨立審查（Augment session）裁定「工單個體幾乎全對，
  錯在把 31 項當無條件整體執行」（PR-0 標「今天」兩日未動＝容量的 live 證據）。修訂：①§4 改為
  兩層執行政策（無條件核心/條件層）並取得權威，07-06 原順序降為歷史對照；②§1 新增 G-1（D-A
  驗證閘）、§3 新增 W-12（判決，判準釘死）；③PR-11/12/13/16 降為條件層（13 帶具名提前條款）；
  ④W-6 提前為校準運行（解除 W-1/PR-13 硬依賴）；⑤W-1 加報告可觀測性（建言後續段＋回應狀態行）；
  ⑥PR-2/PR-18 範圍補 repo CLAUDE.md 同步、W-10 補④定位句雙平面化。工單內容與 07-05/07-06
  審查紀錄全數保留。（Augment／第四輪審查 session）

- 2026-07-07（第五輪——產品向審查）：同日以產品/架構視角複審。核心裁定：全隊列修輸入／triage
  迴路（賭注 A），但 owner 出席的內在動機在產出側——發布迴路持有唯一外部硬回報（/hire 攬客、
  可引用作品），而 31 項中直接服務發布的僅 W-6 一項、無任何項降低內容生產成本；owner 的
  revealed behavior（plan/curation/goals/todos 四面一致迴避）指向「動機問題」與「拓撲問題」
  同樣可能。修訂：①§0 新增雙賭注（A=對話控制台、P=發布引擎）與判決矩陣，P 信號與 G-1 同窗
  取證、不影響 A 判準計算；②§3 新增 W-13（內容管線接種：/build-log 例行化＋兩筆既有內容提案
  升格追蹤，零後端 code）；③W-12 判決書同場記錄 P 信號與矩陣結論；④§4a 並行列加 W-13；
  ⑤§7 補 PARA 存廢掛雙判決後的下一輪；⑥report-contract v2.1：KPI scoreboard 固定發布 cadence
  行。明拒（記錄防翻案）：agent ops cockpit（反面教材重演）、對話側 publish（owner 鐵則）、
  新 content type（現有型別足）。（Augment／第五輪產品審查 session）

- 2026-07-10（第六輪——codex 第三方審查＋owner 裁決）：codex 獨立審查落檔
  docs/reviews/codex-review-2026-07-10.md；Claude cross-review：九條事實斷言經 fresh-context
  verifier 逐條核實 9/9 PASS，B-1〜B-5 CONFIRMED、B-6 needs-human。owner 六問裁決：
  Q1＝全核心保留、以最佳實踐標準執行（不縮隊；EXPERIMENT SLICE＝不可滑骨幹）；
  Q2＝節奏承諾（第一波＋W-5 於 07-10/11 收工）＋W-5 最遲日 07-17 重開標記（§1 G-1 列）；
  Q3＝W-1 完整版提前至 W-5 同步（§4a 第一波，B-3 消解）；Q4＝接受 owner-present 不可觀測、
  §7 句誠實化、不加記錄機制；Q5＝W-12 判決書固定記三個發布階段數（B-5 消解）；
  Q6＝日報 cadence 留待 W-1 安裝時定——owner 反駁成立記錄：報告未讀因系統未完善，且
  Jul 2026 新文章已發布（賭注 P 信號已流動）。計數修正（B-1）：現況＝34 執行單元
  （20 PR＋13 W；19 含 a/b）＝28 核心＋4 條件＋2 固定時點——第四、五輪淨增單元而未重述總數。
  templ 議題維持排除（W-12 判決後依矩陣）。（Claude／cross-review session＋owner 裁決）

- 2026-07-10（第六輪收尾——alignment 和解＋開工定案）：codex alignment
  （docs/reviews/codex-alignment-2026-07-10.md）Q1–Q5 ALIGNED（各附翻案條件，**其 Q1 翻案條件
  採納為本次衝刺的失敗判準**）、Q6 DISAGREE。Claude 裁定 Q6 codex 立場成立（owner 反證支持
  賭注 P、非日報歸檔 cadence）——W-1 安裝時預設採「日刷 latest＋耐久檔僅週報與 check-in」，
  owner 終裁。Q5 資料源錯誤（07-10 初稿誤記 brief content_pipeline）經 verifier 證實後更正
  （W-12 行）。對話層 Control Plane 提案處置：兩個 drift 斷言 verifier 證實——agent.go
  agent_schedule 註解併入 PR-3；frontend AgentPlatform 'system' 殘留登記為待查 finding
  （先查 system 化石事件的渲染路徑再定修法，不盲刪）；提案整體（work_items 五表 execution
  ledger／docs/operating-model 樹）**掛 W-12 判決後依矩陣觸發，與 templ 同閘**——不預先建
  平台；AGENTS.md 收斂＋@import 搭 W-10 docs 輪。codex brainstorm 採納 1–3（手動 prompt
  實驗，隨 W-5/W-6 owner 出席時試）＋5（搭 W-13），4/6 停放。附帶發現：para-semantic-contract
  「project 軸 0 rows」已陳舊（DB 現有 4 projects）＋ koopa0.dev goal/project 分類與記憶
  記錄互斥 → koopa0.dev 是否開 maintained project 掛下一輪 owner 裁決。（Claude／和解
  session＋owner 裁決）

- 2026-07-10（開工 GO）：codex 對第一波出具 GO（無阻斷項），三個 watch item 落帳：①W-12
  latency 起點事件修正——首次進 review＝`created` 事件（payload.status='review'），`to:'review'`
  ＝revision 重進（trigger 原文驗證）；②G-1 窗開＝W-5＋W-1 canonical 安裝雙完成（單一完成
  邊界）；③PR-0 staging 紀律註記。分工定案（07-10 二稿，owner 拍板）：實作＝Claude Code 新 session（PR-0/1/19a 用
  Sonnet+medium、PR-5 用 Fable+high）、**per-PR 開工指導＋驗收＝codex supervisor session**
  （5.6 sol）、程序協調＋W-1 定稿＋W-5 陪跑＋PR-2 mini design pass＝本指導 session、
  merge＝owner。（Claude／指導 session）

- 2026-07-10（PR-0 reconciliation——coordination session）：§1 存檔「DB 13MB 無任何備份」
  在源碼層錯誤——koopa0dev 的每日備份自始存在於 `Koopa0/server`，owner 於 VPS 實測四探針
  全綠（E1）；bucket 私有經 dashboard 截圖證實（E2），「勿用公開資產桶」理由撤銷。**owner
  裁決：PR-0 收斂為 docs-only**——作法 1／7 的備份硬化登記為 repo-B candidates（**NOT
  scheduled**，歸屬與排程待 owner）。E1–E6 已執行，**證據已交 acceptance session，最終
  committed-HEAD acceptance pending**（本行不代表 PASS；PASS 與「完成紀錄」欄由獨立驗收
  session 於通過後填）。鎖定決策：E4＝`SET LOCAL koopa.actor='claude'`（只避免 human-only
  指標被 16 筆污染，`review_period.goals` 仍因降級剩 5，非「全然不受影響」）；E5＝2 project
  掛 goal、2 project 只掛 `area_id='日語'`/`goal_id=NULL`；E6＝`/api/search*` 10 req/10s
  per IP Block 使用中（dashboard，`tofu` 不還原）。作法 2 oracle 改為 dump 自身 COPY 行數
  逐表 diff（非 prod、非三表）；作法 6「修 area neglect 假陽性」理由為誤已改寫（掛載零事件、
  snapshot 不追溯，價值在 projects_total 與未來歸因）；作法 8 hermes spec owner 裁定含入並修
  兩處事實漂移。restore runbook 缺 `ON_ERROR_STOP`＝confirmed correctness finding，列 repo-B
  candidate #1。docs-only 分支已推 `docs/pr-0-ops`；本次 reconciliation 不動「完成紀錄」欄、
  不開 PR、不宣告 PASS。（Claude／coordination session；非驗收）