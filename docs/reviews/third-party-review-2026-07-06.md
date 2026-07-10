# 第三方對抗式審查 — work-orders-2026-07 實作計畫

> **審查者**:獨立 Claude session(fresh context,與 2026-07-05 審查 session 無關)。
> **方法**:嚴格兩階段防 anchoring——Phase 1 在**未讀** work-orders-2026-07.md 與
> report-contract-v2.md 的狀態下,以 live MCP read-only 觀測(brief ×6、review_period ×2、
> project_progress、list_todos、list_content、search_knowledge ×3)、公開站 API 實測、
> auggie 語意地圖、read-only 盤點 subagent(隔離兩份凍結文檔)獨立形成結論並凍結;
> Phase 2 才開檔逐條對照。全程 read-only,僅寫入本報告檔。
> **基準時點**:2026-07-06(HEAD = `6f32b6f2`,2026-07-03 18:19 +0800;PR-0 未動工;
> 兩份凍結文檔 untracked、hermes-proposals-push-spec.md 有未提交修改)。
> 斷言標注:**Fact**(附出處)/ **Inference**(附推理)。

---

## 1. Phase 1 獨立結論(凍結原文,未回改)

> 以下為 Phase 2 開始前凍結的原文,一字未動。

### 前 5 大問題(獨立判斷)

**P1|執行迴路單向:所有「關閉」動作堵在 admin,而 owner 不在 admin。**
Fact:35 天窗(6/01–7/05)todos 開 43 完 1、active_days 7/35(review_period);claude 建立的「/hire 頁」todo 已於 PR #21/22 出貨(7/01–7/03 merged)卻仍躺 state=inbox;daily plan item 完成率恆 0(7/05、7/06 各 1 項 planned、0 done/deferred);2026-07-02 hermes 22 筆提案卡死 inbox(docs/claude-mcp-feature-requests.md 記錄)。
Inference:這不是紀律問題,是拓撲問題——每條 agent 迴路的關閉半邊(clarify/complete/triage)都被設計成 admin-only,但 owner 的實際工作介面是對話與 repo。系統持續進水、幾乎不出水。

**P2|知識引擎對中文檢索失效——對這個以繁中為主要書寫語言的 owner,是第一級缺陷。**
Fact:`search_knowledge("成本意識")` 回 0 筆,但語料中就有已發佈文章《每一行程式碼都是未來的帳單:Go 工程師的成本意識》;公開站 `/api/search?q=成本意識` 同樣 0 筆;英文 query(escape analysis)兩面都命中。
Inference:FTS 的 english text-search config 無法斷 CJK 是共同根因;且 MCP 面 0 命中意味語意(pgvector)分支也未產生貢獻——embedder 未配置於 MCP 部署、或 embedding 未回填、或 RRF 未生效,三者其一(需 DB/env 取證)。

**P3|完全沒有資料庫備份——單 VPS named volume 是唯一副本。**
Fact:盤點 agent 全 repo grep(pg_dump/crontab/snapshot/barman/wal-g/pgbackrest/restore)無任何 DB 備份命中;postgres 僅 docker named volume `pgdata`;`deploy.yml` 部署流程含 `git reset --hard` + `docker compose up -d --build`,部署前不 dump。
Inference:activity_events 是全系統唯一不可重建的資產(audit 史、review_period/project_progress 的地基);content 至少還有 Obsidian 上游。volume 損毀、誤操作或 compose 配置錯誤即全損。這排在所有功能工作之前。

**P4|PARA 承諾層與現實雙重脫勾:資料斷鏈 + 承諾通膨。**
Fact(斷鏈):4 個活 projects 全部 goal_id=null、無 expected_cadence;21 條 goals 的 projects_total 全 0;上週窗(6/29–7/06)6 areas 全報 neglected=true、activity_count=0,但同窗實際有 todo 完成(6/30)與文章發佈(7/03)——todo→area 只經 project.area_id、content→area 只經 project_id,鏈沒掛就歸零(假陽性)。
Fact(通膨):21 條 in_progress goals + 91 milestones 全部 6/24 08:06–08:10 批次建立;15 個 milestone 完成中 13 個是 6/25 04:21–04:23 兩分鐘內補記;6/26 之後 organic 完成 = 0;多條 goal description 仍含「待你給」「模組數你給」等未回答 placeholder。
Inference:goal/milestone 層是 6/24 的一次雄心快照,不是活的承諾集;真實工作發生在 4 projects + 1 recurring habit + 內容產出上。momentum/retro 工具讀著失真的圖在回答。

**P5|情報面腐蝕群:單項皆小,合計侵蝕「code is authority」。**
Fact:`daily_plan_items.status` 無任何 production 寫入路徑(僅測試 UPDATE;brief.go:434-438 註解自認);`cmd/app/routes.go:79` 註解稱 fallback 為 'system' 而實際為 'human'(middleware.go:8、tx.go:24、semantic contract 一致);`internal/content/handler.go:26` 留有已退休 learning 子系統的 stale comment;前端 `article.service.ts:17,42`、`content.service.ts:24,30` 仍帶 backend 已無的 `tag?` 參數;`hermes-proposals-push-spec.md` 引用不存在的 `brief-proposals-section-spec.md`;前端 89 個 spec 檔不在 CI 跑(CI 前端 job 只 lint+build)。
Inference:對一個把「程式碼即權威」立為制度的系統,這些殘缺正是 docs/README.md 自己列的 drift-check 提案(未實作)要抓的東西。

### 前 5 優先動作(獨立判斷)

**A1|備份先於一切:pg_dump 每日 cron + 部署前 dump + 離機副本 + 一次還原演練。** 半天工作量,消滅唯一的全損風險。(對應 P3)

**A2|修中文檢索:先取證(embedding 覆蓋率 SQL、MCP 部署 GEMINI_API_KEY)、再決定 vector-first-for-CJK 或 pg_trgm/pgroonga;無論選哪條,加一條 CJK query 的 integration test 釘住。**(對應 P2)

**A3|把關閉迴路帶進對話:最小工具集 = `clarify_todo`(caller-scoped,inbox→todo)+ `list_todos` filters(state/created_by/since)。** 即 feature-requests 的 F1+F3。決策仍是 owner 的(在對話中口頭裁決),agent 只做被授意的簿記;audit actor 記 agent、可回復、不含 publish/activate/跨 creator。(對應 P1)

**A4|PARA 一次性修復+收斂:4 projects 掛上 goal/area(一次 admin session);21 goals 收斂到真正在推的(≤5 條 in_progress,其餘 on_hold/abandoned);milestones 隨 goal 收斂裁併——證據(6/26 起 organic=0)已足,不必再等兩個月。**(對應 P4)

**A5|腐蝕清單一次清:status 死欄位做決定(給寫入路徑或移除)、兩處 stale comment、tag 死參數、dangling doc 引用、前端測試進 CI。每項一個小 commit。**(對應 P5)

### 附:凍結時對幾個已知爭點的獨立立場(供 Phase 2 對照)

1. **daily-plan 子系統**:活的——hermes 於 7/05 07:56、7/06 07:43(台北)連續兩天透過 plan_day 寫入今日 plan。專屬足跡 ~2,959 行,相對其實現價值(每天指向 1 個 todo)過大;status 欄位已死。但「立即全砍」會切斷 hermes 剛起步兩天的 planner 實驗,且 brief(reflection) 的 plan-vs-actual 問法(「我承諾的做了沒」)與 review_period(「這段時間發生了什麼」)**語意不等價**——前者有承諾分母,後者沒有。我的獨立立場:縮編(砍 status 欄位與 builder UI 可議)+ 給 hermes 實驗一個明確觀察窗,不立即全砍。
2. **agent 觸碰 owner todo 的安全模型**:硬 gate 不可能(MCP call 無 cron-vs-chat 信號,para-contract §9 已認定),prose 規則+audit+可回復性是誠實的形狀;真正該限制的是「工具的寫入集」——triage 類工具不應含 done/dismissed/archived 等終態(終態留在 resolve_todo 的自建範圍),使最壞誤用=可逆的重新歸檔。
3. **「對話+報告=控制台、admin=後場」心智模型**:方向對(owner 行為已如此),但有兩個結構性盲點:(a) 對話面**看不到 inbox 佇列**(brief 無 inbox section,capture 後不可見)與**其他 agent 的 caller-scoped 項目**——全局視野目前只存在於 admin;(b) 決策若只發生在對話而 agent 不回寫,就沒有記錄——回寫工具(A3)是這個模型能否成立的前提,不是加分項。
4. **milestone 判準**:問題根源是 goal 通膨,milestone 只是症狀;以「organic 完成數」做判準方向對,但 deadline 設在 9/01 太遠——證據已經齊了。

---

## 2. 對照結果總覽

我的 5 個獨立問題,計畫命中 4 個(P1→D-A/D-B/PR-5/W-5、P3→PR-0、P4 通膨半→3.5/DA-2、P5→PR-3/PR-8):獨立收斂度高,計畫的主幹是對的。**未命中的是 P2(中文檢索)與 P4 的斷鏈半(projects 掛鏈)**,加上三個計畫內部的不一致(§4 詳述)。

## 3. §1 鎖定決策逐列 verdict

| # | verdict | 證據(一句) |
|---|---|---|
| D-A(決策場=對話+報告)| **AGREE**(owner-locked)| 與我 Phase 1 P1 獨立收斂;live 佐證:7/35 出席、shipped 工作躺 inbox——owner 確實不在 admin |
| D-B(先 triage_todo 後報告按鈕)| **AGREE**(owner-locked)| 「記錄的實質=DB state change+audit」正確——`withActorTx` 保證 actor 落 audit(internal/mcp/tx.go);次階段按鈕建議加一次 confirm(誤點防護),不改方向 |
| D-C(Telegram 降級鬧鐘)| **AGREE**(owner-locked,附觀察)| push-to-ignored-channel 是噪音;但停用後**全系統只剩「報告」一個 pull-back 通道**——建議在 W-9(本週真 deadline)主動實測鬧鐘,不等失效才發現;hermes-proposals-push-spec.md 的 Telegram nudge 段與 D-C 矛盾,W-4⑤ 需一併改 |
| 3.3(batch=對話一次回覆;不做 category 預授權)| **AGREE**(owner-locked)| 「判斷不可預授權」與 F5 的正確拒絕;22 筆塞車的癥結是裁決通道不是裁決粒度 |
| 3.4(digest weekly、恆私有、逐期決定公開)| **AGREE**(owner-locked)| 復用 propose_content 既有面(catalog.go),零新機制;私域排除是 prompt 層——真正的 gate 是 owner publish,可接受 |
| 3.5(goals in_progress 只留 5)| **AGREE**(owner-locked)| live 驗證:21 條全 in_progress、全 6/24 批次(brief morning);21−5=16 與 PR-0 SQL 預期筆數一致;description 殘留「待你給」佐證通膨診斷 |
| 3.6(RSS 砍 curation UI、60 天 retention、feed 修剪)| **AGREE**(owner-locked)| 「1585/0 curated=沒人走的路」與 automate-or-drop 原則一致;1585 本身我無法驗證(見 §8),但 0-curation 的方向與 content_pipeline=[]、entries 僅出現在 highlights 相符 |
| DA-1(daily-plan 立即砍除)| **MODIFY** | 砍除本身成立:status 欄位零 production 寫入(Fact:grep 僅測試檔)、0/6 follow-through 與我觀測一致;但①「review_period 取代 reflection」**語意不等價**——reflection 有承諾分母(plan-vs-actual),review_period 沒有;誠實的表述是「**放棄 plan-vs-actual 這個問法**」,而非「已被取代」;②hermes 7/05、7/06 連續兩晨仍在寫 plan(Fact:committed_todos.selected_by=hermes)——W-4 前置正確,務必嚴格先行;③PR-2 scope 缺前端消費者(見 §5 PR-2) |
| DA-2(milestones 凍結+9/01 判決)| **MODIFY(輕)** | 我 Phase 1 主張立即動;對照後修正——3.5 先行讓評估窗變乾淨(活 goal 只剩 5 條、~23 milestones),「等」的成本已低,凍結+日期 tripwire 符合專案慣性(para-contract §6 同款);但判準必須**現在釘死**:窗起點(建議 7/05)、organic 的操作化定義(非同批:同 actor 5 分鐘內 >2 筆不計)、資料源(activity_events,PR-6 後含 occurrence)——否則 9/01 會重演定義之爭 |
| DA-3(propose_* 三件組保留)| **AGREE** | proposals 迴路的兩半剛落地(PR #20 brief section+hermes push spec)——砍了才是浪費;「低頻使用形狀正確的工具不是錯誤」與 zero-data≠zero-need 一致 |
| DA-7(001/002 凍結,003+ append-only)| **AGREE** | 6/25 事故(edit-in-place 打掛 running DB)已付學費;PR-2/6/13 均遵守 append-only,自洽 |
| Option B 維持 | **AGREE** | 封閉 roster+transport 邊界,重審結論與 para-contract §9 一致;PR-4 順手補了 retired-caller 的 fail-loud,是正確的最小加固 |
| agents 表保留+砍 profile 頁 | **AGREE** | FK 錨是 Option B 唯一硬防線(activity_events.actor REFERENCES agents);profile 頁過不了「每月會來嗎」測試 |
| 留 Angular | **AGREE** | 89 spec/594 it()、zoneless 已驗證;重寫是純 churn,違反收斂 |
| hybrid search/embeddings 凍結不加碼不回退 | **MODIFY——這是全計畫我最不同意的一列** | 「凍結不加碼」可以;但存檔句「CJK FTS…embedding 補償」**被 live 探測證偽**:`search_knowledge("成本意識")` 與公開站 `/api/search?q=成本意識` 皆 0 筆,而語料中就有同名標題的已發佈文章(Fact)——embedding 沒有在任何我可觸及的面補償 CJK。「無害」不成立:公開站搜尋對 3/4 的中文語料是壞的。需要一個小工作項:取證(embedding 覆蓋、MCP 部署 GEMINI_API_KEY)→ 修語意分支 **或** 收斂地砍/藏公開 search UI(用計畫自己的反面教材邏輯:「為 4 篇文檔建 hybrid search」);並更正存檔句 |
| publish 永遠 admin-only | **AGREE** | owner 鐵則;與 chk_content_public_requires_published 的結構防線同向 |
| rs 重寫零耦合 | **AGREE** | 隊列中無任何項依賴它;程序性決策,無可驗證內容 |

## 4. 計畫內部不一致(對照才浮現,三件)

**I-1|W-5「清倉」與報告契約 §5 需要「跨 creator 的 inbox 全量讀取」,但整個 PR 隊列沒有提供它。**
Fact:W-5 要 Claude「列 28 筆」;report-contract §5 要列出「inbox 全部 items——標題、created_by、age」;但 `list_todos` 是 caller-scoped(catalog 描述+code),brief 無 inbox 列表 section,PR-10 只加 `inbox_pending`(**count**),PR-12(filters)在順序上排在 W-5 之後、且未言明是否解除 caller-scope。今天 Claude 經 MCP 只看得到自己的 6 筆,看不到 hermes 的 22 筆。
Inference:28=22(hermes)+6(claude)在數字上剛好對上(live 驗證 claude inbox 恰 6 筆),但讀取面缺口使 W-5 的 playbook 沒有資料源——除非 owner 貼 admin 清單(違背「對話自足」的前提)。**修正:把「inbox 全量讀」明確化(PR-12 提前併入 PR-5 並明文決策 de-scope,或 PR-10 加 `inbox_items` 列表),置於 W-5 之前。** 注意這是語意契約變更(agent 可讀 owner/他人 inbox 項),要寫進 catalog 描述,不能當作 filters 順手帶過。

**I-2|PR-2 的前端 scope 漏了兩個 plan 消費者。**
Fact:`gtd.store.ts:81-83` 的 `plan` rxResource 呼叫 `dailyPlanService.today()`(Todos 頁);Today 頁前端渲染 committed 區(backend `today/handler.go` CommittedTodos)。PR-2 只列「admin Plan 頁+路由+nav+specs 刪除」與 backend Today aggregate 移除。
Inference:照單施工會讓 Todos 頁在 runtime 打 404(rxResource error 路徑有 guard,不至白屏,但是壞味道)。**修正:PR-2 scope 補 `daily-plan.service.ts`、`gtd.store.ts` plan resource、Today 頁 committed 區前端與對應 specs。**(mini design pass 前置已存在,把這兩項寫進去即可。)

**I-3|PR-3 的化石清單不完整。**
Fact:盤點另尋獲 `internal/content/handler.go:26`(learning-studio stale comment)與前端 `article.service.ts:17,42`、`content.service.ts:24,30` 的 `tag?` 死參數(backend contents 已無 tags);另 `hermes-proposals-push-spec.md` 引用不存在的 `brief-proposals-section-spec.md`。
**修正:前兩項併入 PR-3(或 PR-14),dangling 引用隨 W-4⑤ 更新時清。**

## 5. 16 條 PR:存在性/粒度/順序 verdict

| PR | verdict | 一句評註 |
|---|---|---|
| PR-0 備份+goals 降級+rate rule+診斷歸檔 | **AGREE** | 與我 A1 完全收斂且更完整(含 restore 演練、私有 R2 桶、preview-then-UPDATE);唯 cron 無失敗監控——建議 Grafana 加 backup file-age alert(一行) |
| PR-1 deploy gate on CI | **AGREE** | 現狀 deploy 與 CI 並行=紅測試也部署(Fact:deploy.yml 獨立觸發);順序第 2 正確 |
| PR-2 砍 daily-plan | **MODIFY** | 見 DA-1 + I-2;另按 §7 風險清單,`IsCompletedOn` 語意遷移的 mini design pass 前置正確,勿省 |
| PR-3 actor 化石註解 | **MODIFY(擴 scope)** | 方向對(我獨立驗證 routes.go:79 為 stale);按 I-3 補兩處;sqlc regen 提醒正確(COMMENT 是 sqlc 輸入) |
| PR-4 拒絕 non-active caller | **AGREE** | 存檔稱 agents 表有 4 個 retired row(go-spec/koopa0-dev/system/unknown)——若確,則今天 `as:"system"` 能過 FK 落 attribution,這是真洞;fail-loud 正確 |
| PR-5 triage_todo | **AGREE(附一項)** | 安全模型與我 Phase 1 附 2 獨立收斂(prose+audit+寫入集限制;verdict 不含 done ✓ 只動 inbox ✓ cross-creator 因「執行 owner 裁決」語意而必要);**補:驗收加「誤 dismiss 的回復路徑」**(admin 能否把 dismissed 拉回 inbox/todo?今天 advance 動詞未涵蓋,PUT 拒 state 變更) |
| PR-6 habit occurrence 進 audit | **AGREE** | 修「habit 歷史不存在」的真洞(我觀測到 4 天 lapse 完全隱形);actor 語意(agent 代蓋不入 human momentum、獨立區塊呈現)想清楚了;append-only ✓ |
| PR-7 CSP+server.ts 測試 | **AGREE** | 真實 injection 面(escapeXml/RSS/sitemap);與其他 PR 無耦合 |
| PR-8 full-stack CI gates | **AGREE(附順序註)** | 89 specs 進 CI 是我 P5 的直接修復;唯排序偏晚——PR-2 這種大刀落在前端測試進 CI 之前,PR-2 期間請至少本地跑 `npm test`(寫進 PR-2 驗收更好) |
| PR-9 cmd/mcp config 測試 | **AGREE** | cmd/mcp 0 測試屬實(盤點);比照 cmd/app 表驅,粒度剛好 |
| PR-10 brief 加 inbox_pending/dormant_recurring/deadline | **AGREE(附 I-1)** | 三個欄位各對應一個實測盲點(28 積壓隱形、2 habit 沉睡、ヨルシカ票會過期);但 count 不解 I-1 的「列表」需求 |
| PR-11 annotate_todo | **AGREE** | append-only+署名行+cross-creator 僅註記,寫入集設計克制;description 會進 admin markdown 渲染,沿用既有 sanitize+長度上限即可 |
| PR-12 list_todos filters | **MODIFY** | F3 原案是 self-scoped 的省讀;若同時要當 I-1 的跨 creator 讀,`created_by` 參數與 caller-scope 衝突必須明文裁決並改 catalog 描述+hermes spec;並提前至 W-5 前 |
| PR-13 post_status_note | **AGREE** | 「/hire 出貨但 todo 躺 inbox」的正解;agent_notes 無 retention(小,列觀察即可) |
| PR-14 admin IA trim | **AGREE** | nav 4 組+砍 profile 頁+手機 2-tap 驗收,皆過「每月會來嗎」測試 |
| PR-15 feed retention+砍 triage UI | **AGREE** | 3.6 的忠實執行;留 curated_content_id 欄位+COMMENT 誠實化,符合 keep-and-wire |
| PR-16 propose_project 參數(可選) | **AGREE(附)** | 跳過條件健康;但它只服務**新**提案——**既存 4 projects 的掛鏈修復不在任何 PR 裡**(見 §6 B-2) |

**該做而沒列的 PR**(特別覆核 e):CJK 檢索取證+處置(§3 hybrid 列)、既存 projects 掛鏈(§6 B-2)、inbox 全量讀(I-1,可併 PR-5/10/12)。安全類與備份設計:除 MCP_TOKEN 無輪換(Option B 姿態下屬可接受殘餘)外,**此類無其他發現**——PR-0 的備份設計(演練+異地+lifecycle)與 PR-7/8 的安全補課是充分的。被砍功能殘留:song/shelf 零殘留(Fact:全 repo 零命中),僅 I-3 兩處小殘。

## 6. 盲點清單(計畫完全沒碰、但我認為重要)

**B-1|中文檢索斷裂被錯誤歸檔。** 全計畫唯一一處「以錯誤事實為依據的鎖定決策」。詳 §3 hybrid 列。對「個人知識引擎」的宣稱,這不是邊角——是 owner 用自己語言找不到自己知識。

**B-2|既存 4 projects 的 goal/area 掛鏈修復缺席。** Fact:4 projects 全 goal_id=null(project_progress);後果:area 週窗全報 neglected 假陽性、goals projects_total 全 0——而**報告契約 §2 的資料源正是 project_progress/review_period**,W-1 之後每天的報告會建立在失真的 momentum 圖上。10 分鐘 SQL/admin 修復,建議併入 PR-0 的 ops 日。

**B-3|報告單通道無 fallback。** D-C 停 Telegram 後,owner 的唯一 pull 面是報告;報告未被打開時無任何升級機制(計畫 §7 只列了鬧鐘未驗證)。建議:W-9 期間做一次鬧鐘實測;報告連續 N 天未讀的 fallback 屆時再議(先觀察,不預建)。

**B-4|報告契約缺「上週建言後續」段。** 防模板化最有效的機制不是準則,是**回頭看**:每週報告固定一段「上週 N 則建言 → owner 動了哪些/沒動哪些」。它讓建言品質變成可觀測的迴路,也讓「湊數建言」自然出醜。一段 3 行的契約增補。

**B-5|備份 cron 的靜默失敗。** PR-0 驗收是一次性 rclone ls;cron 之後壞掉無人知。Grafana 已在(deploy.yml 有 silence 步驟),加一條 backup file-age alert 即可。

其餘掃描類別(資料完整性 trigger 面、frontend a11y、SSR):**此類無發現**——PR-6 的 trigger 設計、現有 89 specs 與 axe e2e、SSR deep-link 修復(PR #23)覆蓋了我能觸及的面。

## 7. 順序與風險批評

順序主幹正確:PR-0(備份)先於 PR-2(DROP TABLE)——**這個先後關係是全隊列最重要的一條邊,已被滿足**;CI gate 第二;triage 工具最快兌現「系統開始為 owner 工作」。三個修正:

1. **W-5 前必須有 inbox 全量讀**(I-1)。否則清倉 playbook 的第一步就要出隊列外借道(owner 貼清單)。
2. **PR-2 期間的前端回歸依賴本地測試**(PR-8 尚未進 CI)——把「`npm test` 本地綠」寫進 PR-2 驗收。
3. **W-9(ヨルシカ票,本週)與 PR-10(deadline 浮出)的時間錯位**:W-9 靠人記得,PR-10 落地前 brief 不會提醒;計畫已把 W-9 標「本週」,可接受,但這正是 D-C 鬧鐘的第一個實測機會(見 B-3)。

風險面:PR-2 是唯一的破壞性 migration(DROP TABLE),前置(W-4、mini design pass、備份)齊全;PR-5/11 的 prose-not-gate 姿態與 Option B 一貫,審計事後可見(§7 自認),我接受——**誠實地說「這裡沒有硬 gate」比假裝有更安全**。

## 8. 特別覆核清單裁定(a–g)

- **a. DA-1 過當?** 半過當:砍的方向成立(status 死欄位、0/6 follow-through、~2,959 行足跡對 1 item/day 的實現價值),但「review_period 語意等價」不成立(承諾分母消失)——正確的表述是**刻意放棄 plan-vs-actual 問法**,文檔應照實寫;hermes 兩天前才開始每日 plan(7/05、7/06 皆 Fact),W-4 前置必須嚴格先行。詳 §3 DA-1、§4 I-2。
- **b. triage_todo 安全模型可接受?** 可。硬 gate 不存在的前提是結構性的(MCP 無 cron-vs-chat 信號,para §9 已認定);prose+audit+寫入集限制是誠實形狀,與我 Phase 1 獨立設想收斂。更好的形狀(確認 token、時窗授權)在單人信任域內是劇場。唯一補強:誤 dismiss 的回復路徑要有名字(§5 PR-5)。
- **c. 心智模型 v2 反例?** 無致命反例,owner 行為證據支持它;三個隱藏成本:讀取面缺口(I-1,是 v2 能否成立的前提)、單通道無 fallback(B-3)、報告品質即介面品質(契約已設防,補 B-4 更穩)。
- **d. 9/01 判準對嗎?** 凍結+日期 tripwire 的形狀對(且 3.5 先行讓窗變乾淨,推翻我 Phase 1「立即動」的急迫性);但判準要現在操作化:窗起點 7/05、organic=非同批(同 actor 5 分鐘 >2 筆不計)、資料源=activity_events。另:攤平方向若成立,結構應進 goal.description checklist——與 PR-6 的 occurrence 聚合同款「化整為零」思路,自洽。
- **e. 缺漏 PR?** 三件:CJK 取證+處置、既存 projects 掛鏈、inbox 全量讀。安全/備份/殘留耦合:除已列者外此類無發現。
- **f. 報告契約可執行?會退化成模板?** 可執行(輸入=具名工具呼叫、失敗降級有規則、「空建言比湊數誠實」是對的反模板條款);退化風險集中在「每則以下一步收尾」的填充傾向——B-4 的後續段是結構性解法。§5 依賴 I-1。
- **g. 數字抽驗**:7/35 出席 ✓(review_period 6/01–7/05 active_days=7);4 篇公開 ✓(review_period+公開 API 雙源);21 goals 全 in_progress 全 6/24 ✓;milestones 91/15、批次補記 ✓(12 筆落在 6/25 04:21:59–04:23:09,存檔寫 13,±1 屬計法差);「40 開 1 完」≈ 我測 43 開 1 完(6/01–7/05)——completed=1 精確吻合,opened 差 3 應為窗定義+一日漂移,量級與結論不受影響;28 筆=22(hermes)+6(claude)✓(claude inbox 恰 6 筆,live);1585 unread 無法驗證(見 §9)。

## 9. 最終建議

**帶修正照做。** 主幹(備份第一、CI gate、對話式 triage、goal 收斂、daily-plan 退場、報告化控制台)與獨立審查高度收斂,順序的關鍵邊正確。修正七條,按重要性:

1. **B-1**:新增小工作項「CJK 檢索取證+處置」(修語意分支或收斂地砍公開 search UI),並更正 §1 存檔「embedding 補償」句——鎖定決策不能建立在被證偽的事實上。
2. **I-1**:W-5 之前提供 inbox 全量讀(PR-12 提前併入 PR-5 並明文 de-scope,或 PR-10 加 `inbox_items`);寫進 catalog 與 hermes spec。
3. **I-2**:PR-2 scope 補前端消費者(gtd.store plan resource、daily-plan.service、Today committed 前端)+「npm test 本地綠」驗收;DA-1 理由句改為「放棄 plan-vs-actual 問法」。
4. **B-2**:PR-0 ops 日順手做 4 projects 掛 goal/area(10 分鐘),讓報告的資料源從第一天就不失真。
5. **DA-2 判準現在釘死**(窗起點/organic 定義/資料源),9/01 只執行不再議。
6. **B-4**:報告契約加「上週建言後續」段(3 行)。
7. 小項:PR-3 擴 scope(I-3)、PR-5 定義 dismiss 回復路徑、備份 file-age alert(B-5)、W-9 兼做 D-C 鬧鐘實測(B-3)。

不建議停下重想任何主幹決策。owner-locked 各項中,我唯一實質挑戰的是 hybrid search 凍結列的**事實依據**(非其收斂精神)——見修正 1。

## 10. 無法驗證清單(誠實條款)

以下斷言在我的 read-only 通道(MCP 六工具+公開 API+repo)內不可驗證,均**未**採信為 Fact;附 owner 可自跑的 SQL(psql against prod):

| 存檔斷言 | 建議取證 |
|---|---|
| feed_entries 1585 unread / 0 其他 | `SELECT status, count(*) FROM feed_entries GROUP BY status;` |
| daily_plan 共 6 rows 0 done | `SELECT status, count(*) FROM daily_plan_items GROUP BY status;` |
| 'system' actor 化石事件 1 筆;agents 有 4 retired rows | `SELECT actor, count(*) FROM activity_events GROUP BY actor;` `SELECT name, status FROM agents ORDER BY status, name;` |
| DB 13MB | `SELECT pg_size_pretty(pg_database_size(current_database()));` |
| embedding 是否補償 CJK(B-1 的根因分流) | `SELECT count(*) FILTER (WHERE embedding IS NULL) AS missing, count(*) AS total FROM contents;` + 確認 cmd/mcp 部署環境是否設 `GEMINI_API_KEY` |
| S4(admin 編輯時段)從未發生、「報告是 owner 出席率最高表面」 | owner 自證(行為事實,系統無記錄) |
| hermes 側現狀(22 筆的當前分佈、pa-brief 排程) | hermes repo/ledger,不在本 repo 通道內 |

另:兩份凍結文檔與本報告皆 untracked、`hermes-proposals-push-spec.md` 有未提交修改——**working tree ≠ repo**,建議 PR-0 的 docs PR 一併收納(本報告除外,owner 決定去留)。

---

## 11. 補充覆核:07-06 追加項(鏡頭 h/i)——和解輪輸入

> 時序事實:本報告主體完成於 07-06 09:59;work-orders 於 10:00 追加 PR-17/PR-18/W-10/W-11
> 並標「pending-reconciliation:第三方 review 進行中」(§8 變更日誌,work-orders:266-269)。
> 本節即該和解的第三方輸入,以同樣紀律獨立取證後下判。

### 11.1 鏡頭 h — search_knowledge 存廢/改名/visibility(對 PR-18)

先釘事實(Fact):`InternalSearchContents`(internal/content/query.sql:63-78)`WHERE status != 'archived'`
——draft/review/changes_requested/published 全可搜;`InternalSemanticSearchContents`(:80-96)
**鏡像同一 visibility**(兩分支一致,無不對稱 bug);公開路徑(PublishedForRSS :98-103、
SimilarContents :252-260、PublishedWithEmbeddings :262-266)全部 `status='published' AND is_public=true`
——**公開面的機密邊界是結構性的**。另:FTS 用 `websearch_to_tsquery('simple', …)`(:60,:73)
——'simple' config 同樣不斷 CJK,B-1 的根因在此再獲一證。

| 子判斷 | verdict | 論據 |
|---|---|---|
| 存廢:保留 | **AGREE** | 它是 MCP-only context 的唯一 corpus 檢索窗(本審查 session 即活例——我只能經它觸及 contents);list_content 是 caller-scoped 回讀,不可替代。附帶條件:keep 的價值被 B-1(CJK 失效)腰斬——保留判斷不變,修復依賴不變 |
| 改名 search_content | **AGREE** | 雙平面下「knowledge」屬 vault,名字確實說謊;更強的論據是家族一致性:list_content/propose_content/revise_content 已成隊,search_content 歸隊。排在 W-2 前(「prompt 只寫一次新名」)是正確的依賴排序 |
| visibility 維持(非 archived 全搜)+測試釘住 | **AGREE = feature 非 leak,但補一刀** | (i) 信任域封閉:transport gate + closed roster,讀者全是 owner 的 staff;(ii) 真正的洩漏邊界(公開站)已結構性隔離(上列 Fact);(iii) pipeline 語意上 draft/review 是協作中工件——propose→review→revise 迴路需要可搜性(查重、續稿);(iv) owner 私密寫作在 Obsidian,不在此層(他自己的架構決定)。**但**:realistic 的洩漏向量不是「agent 讀到 draft」,是「agent 把 draft 內容再發佈到下游」(如 digest 引用未發佈稿、owner 再公開 digest)。而 `SearchKnowledgeOutput` 的結果列**不帶 status/is_public**(internal/mcp/search.go:70-75;live 結果實測欄位僅 id/source_type/title/slug/content_type/excerpt/created_at)——caller 拿到 draft 也無從得知,「未發佈不外引」紀律無法執行。**PR-18 應加:結果 wire 帶出 `status`(建議含 `is_public`)+ description 明文宣告 visibility(計畫已傾向)+ 釘住測試(計畫已列)。**三者齊了,「維持」就是安全的 feature |

### 11.2 鏡頭 i — Zed/Google 級紀律 delta(對 PR-17/W-10/W-11)

**追加項自報數字全數驗實(Fact)**:integration_test.go 94,191 bytes ✓;測試內 `context.Background()`
恰 15 處(10 檔)✓;W-10 對 F4 的「過時已修」✓(live project_progress 已回 4 projects)。

- **PR-17**:**AGREE**——它把三條既有教訓直接寫進了範圍(deadcode 輸出≠刪除清單、keep-and-wire 分類、
  產品語意候選「只分類不擅刪,列單給 owner」),這是對的形狀。兩個 MODIFY:①「第二個 integration 檔」
  語焉不詳——>40KB 的實際名單是 mcp 94K、goal 57K、todo 42K(Fact:find -size +40k),點名進範圍;
  ②schema 級 vestigial(contents.ai_metadata、feed score——semantic contract §6C 自認)不是 Go deadcode
  可見的,勿混入本 PR,列進 owner 清單即可(migration 屬 DA-7 append-only 另批)。
- **PR-18**:**AGREE + 11.1 的 wire-status 增補**;順手併一個同類命名修復:`internal/url` 遮蔽 stdlib
  `net/url`,唯一 production 消費點被迫別名(collector.go:13 `net/url` + :22 `koopaurl "…/internal/url"`,
  Fact)——rename(如 `internal/canonurl`)或折進 feed/collector,2 個消費者,成本一杯茶。
- **W-10**:**AGREE**——F1–F6 disposition 對照我 Phase 1 的獨立判讀全部一致(F1 改形為 annotate、F5 拒
  =判斷不可預授權、F6→PR-13)。增補三件同類衛生:①dangling `brief-proposals-section-spec.md` 引用
  (hermes spec 引用不存在的檔);②para-semantic-contract.md 不在 docs/README 分類表;③docs/README
  自己列的 4 條 drift-check 提案(README.md:41-62)**落地 #1 或刪除該節**——#1(path-existence check,
  ~20 行 script 掛 CI)恰好能自動抓到 ① 這類 rot,是「結構性防呆優於紀律」哲學的最便宜實例。
- **W-11**:**AGREE**——把「never force push / 一律 PR」從 prose 變結構,方向與全系統一致;require CI
  green 依賴 PR-1 的 job 合併,順序註記(隨 PR-1 落地即設)正確。

**主 session 漏掉的缺口**(依價值排序;linter 面掃描基礎=.golangci.yml 現行 23 linters):

1. **CI 從不 build Docker image**——deploy 在 VPS 上 `compose up --build`,CI 綠≠image build 得過;
   Dockerfile 壞掉要到 prod 才發現。PR-1/PR-8 加一個 `docker build`(或 compose build)dry job。
2. **import 三組分組規則無執行器**——package-organization.md 明文規定,無 linter 背書;加 `gci`
   (Zed/Google 都是 formatter-enforced,不靠人肉)。
3. **no-framework 規則無執行器**——chi/gin/echo/testify 禁令是 prose;`depguard` denylist 一段配置
   把它變 CI 事實。與 forbidigo 已用於 tx 契約同一哲學,補齊即可。
4. **bodyclose + noctx 缺席**——collector 是真 HTTP client(SSRF-hardened 但 body 洩漏/無 ctx 請求
   這兩類 linter 沒開)。
5. **`go test -shuffle=on`**——CI 一行,抓測試順序依賴;Google 標配。
6. fuzz 面**無重大缺口**(Fact:已有 23 個 Fuzz target、分布 15 個測試檔,覆蓋 auth/PKCE/changelog/
   graph 等——自報「嚴謹度對齊」在這面站得住;此數字初稿誤計為 10,經獨立驗收更正);小候選:
   DeriveSlug、canonical URL normalize。
7. coverage floor 已被 07-06 追加的「二階段(觀測值−2%)」處理 ✓,此類無另發現。

**明拒清單裁定**:六項(CONTRIBUTING/CODEOWNERS/issue templates/CodeQL 付費/commit-lint CI/
license-header bot)**全數同意拒絕**——單人 closed repo 的社群儀式定性準確。唯 commit-lint 附一句
保留:本地 commit-message hook 只約束 Claude Code 通道,codex/手動 commit 不受管;若 conventional
史未來變成自動化輸入(changelog/build-log 解析),5 行 CI regex 再撿回來,現在拒得對。

### 11.3 對 §9 最終建議的增補(和解輪採納清單)

維持「帶修正照做」。追加修正(接續 §9 編號):

8. PR-18 範圍補:search 結果 wire 帶 `status`/`is_public`;`internal/url` 改名併入。
9. PR-17 範圍補:點名 goal 57K、todo 42K 兩檔;schema vestigial 明文排除在外(只列單)。
10. PR-8 追加:docker-build dry job、`-shuffle=on`、gci、depguard、bodyclose、noctx
    (六件都是配置級,半天內);W-10 追加:dangling 引用清理 + docs/README drift-check #1 落地或刪節。

### 11.4 h/i 覆核的無法驗證項

「遠端 agent 唯一檢索窗口」中 Cowork planner 的實際 transport(HTTP vs 本機 stdio)——我以本 session
(HTTP 通道)為活例支持 keep,但 Cowork 端配置在 repo 外,未驗;PR-18「~10 Go 檔」的改動面估計未逐檔
核(rename 機械性高,風險低)。

---

## 附:審查 stop report

- **任務型別**:audit(read-only)+ cross-review(對另一 session 的凍結計畫)
- **檔案變更**:僅本檔(`docs/reviews/third-party-review-2026-07-06.md`,新增);scratchpad 有 Phase 1 凍結副本(session-local,不在 repo)
- **跑過的驗證**:live MCP read-only ×13 次呼叫、公開 API ×4、repo grep/read、盤點 subagent(隔離凍結文檔);§11 追加輪:work-orders 更新版全文、query.sql visibility、.golangci.yml、fuzz/測試規模/import 探針,全 read-only;**未跑**:build/test(無 code 變更,不適用)、任何 DB 直查與 mutation 工具(審查紀律禁止)
- **範圍確認**:未觸碰 MCP mutation 工具;未修改任何既有檔案
- **獨立驗證狀態**:本報告由 fresh-context session 產出,即為對 2026-07-05 審查的獨立第二意見;報告本身經 fresh verifier subagent 兩輪讀回驗收——第一輪 7/7 PASS(含 Phase 1 凍結逐字比對),第二輪(§11)6/7,抓出兩處數字錯誤(Fuzz target 10→23、linter 22→23)已更正——驗證不自驗的迴路實際發揮了作用
- **working-tree 警示**:如上——三份 docs untracked、一份 modified,均非本審查所改
