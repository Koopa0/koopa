# koopa0.dev 功能測試清單

> **Date**: 2026-03-18
> **建議順序**: 第一層 → 第二層 → ... 逐層測試，前層不過不測後層

---

## 第一層：基礎設施

| # | 測試 | 方法 | 預期結果 | ✅ |
|---|------|------|---------|---|
| 1 | Health check | `curl https://koopa0.dev/bff/healthz` | `ok` | |
| 2 | DB readiness | `curl https://koopa0.dev/bff/readyz` | `ok` | |
| 3 | Migration | 檢查 server logs 有 `migrations: applied successfully` | 22 tables created | |
| 4 | Google OAuth | 瀏覽器開 `/login` → Sign in with Google | 成功導向 `/admin` | |
| 5 | Token refresh | 等 access token 過期 → 操作任何 admin 頁面 | 自動 refresh，不被踢出 | |

---

## 第二層：Webhook Pipeline（核心 data flow）

| # | 測試 | 方法 | 預期結果 | ✅ |
|---|------|------|---------|---|
| 6 | Obsidian note sync | Push 一個 .md 到 vault repo（非 10-Public-Content/） | Logs: knowledge note synced + activity event recorded | |
| 7 | Public content sync | Push 到 `10-Public-Content/*.md` | content-review flow 觸發 → review queue 出現一筆 | |
| 8 | Other repo push | Push 到 resonance 或其他 repo | Logs: project-track submitted + activity event (source: github) | |
| 9 | Notion project update | 在 Notion 改一個 Project 的 Status | Logs: `project synced from notion` + `recording project activity event` | |
| 10 | Notion task Done | 在 Notion 把一個 Task 標 Done | Logs: `task_status_change` activity event + `project activity updated` | |
| 11 | Notion task status change | 在 Notion 把 Task 從 To Do → Doing | Logs: `task_status_change` activity event (status: Doing) | |
| 12 | Notion book read | 在 Notion 把一本書標 Read | Logs: `book_progress` event + `bookmark-generate submitted` | |
| 13 | Notion goal update | 在 Notion 改 Goal status | Logs: `goal synced from notion` + `recording goal activity event` | |
| 14 | Self-loop protection | 確認 bot push 不觸發 sync | Logs: `ignoring push from bot` | |
| 15 | Webhook dedup | 手動重送同一個 GitHub delivery ID | 第二次 logs: `replay detected` | |

---

## 第三層：Admin Dashboard

| # | 測試 | 方法 | 預期結果 | ✅ |
|---|------|------|---------|---|
| 16 | Stats overview | 開 `/admin` | 11 張 stats cards 有數字 | |
| 17 | Drift detection | Dashboard drift section | 顯示 area 分佈（需先有 goals + activity data） | |
| 18 | Learning dashboard | Dashboard learning section | 顯示 notes/spaced/activity/top tags stats | |
| 19 | Recent articles | Dashboard 下方 | 顯示最近 5 篇文章（可能為空） | |
| 20 | Recent projects | Dashboard 下方 | 顯示專案列表 | |
| 21 | Pipeline: Obsidian Sync | 點 "Obsidian Sync" 按鈕 | Logs: sync 執行 → 完成 | |
| 22 | Pipeline: RSS Collect | 點 "RSS Collect" 按鈕 | collected_data 有新資料 | |
| 23 | Pipeline: Notion Sync | 點 "Notion Sync" 按鈕 | Projects + Goals upserted from Notion | |
| 24 | Pipeline: Reconcile | 點 "Reconcile" 按鈕 | Logs: reconciliation 執行 | |

---

## 第四層：Content CRUD

| # | 測試 | 方法 | 預期結果 | ✅ |
|---|------|------|---------|---|
| 25 | Create article | `/admin/editor` → 填寫 title/slug/body → Save Draft | 201 Created，dashboard 出現 | |
| 26 | Edit article | 開已存在的文章 → 修改內容 → Save | 200 OK | |
| 27 | AI 潤稿 | Editor → 點紫色 AI 潤稿按鈕 → 等 polling 完成 | Violet banner 出現三選項 | |
| 28 | Publish | 手動發佈或 Review queue → Approve | Status 變 published | |
| 29 | Public view | 瀏覽器開 `/articles/{slug}` | SSR 渲染完整文章 + TOC + related | |
| 30 | Search | 開 `/search` → 輸入關鍵字 | 回傳搜尋結果 | |
| 31 | RSS feed | 開 `/feed.xml` | Valid RSS XML with published content | |
| 32 | Sitemap | 開 `/sitemap.xml` | Valid XML with all routes | |
| 33 | Create project | `/admin/project-editor` → 填寫 → Save | 專案建立成功 | |
| 34 | Public project | 開 `/projects/{slug}` | SSR 渲染 case study 頁面 | |

---

## 第五層：Tag System

| # | 測試 | 方法 | 預期結果 | ✅ |
|---|------|------|---------|---|
| 35 | List tags | `/admin/tags` Tab 1 | 顯示 canonical tags（可能為空） | |
| 36 | Create tag | 新增 slug: `go`, name: `Go` | 成功建立 | |
| 37 | List aliases | `/admin/tags` Tab 2 → Unmapped filter | 顯示 B1 sync 累積的 raw tags（需先有 note sync） | |
| 38 | Map alias | 選一個 unmapped alias → 映射到 canonical tag | 成功映射 | |
| 39 | Confirm alias | 對一個 pending alias 點 Confirm | 狀態變 confirmed | |
| 40 | Reject alias | 對一個 alias 點 Reject | 狀態變 rejected | |
| 41 | Backfill | 點 Backfill 按鈕 | 顯示 notes_processed / tags_mapped / tags_unmapped | |
| 42 | Merge | 建兩個重複 tag → Merge source into target | 顯示 aliases_moved + notes_moved + events_moved | |
| 43 | Delete tag | 刪除沒有引用的 tag | 成功刪除 | |
| 44 | Delete tag (has refs) | 刪除有 alias 引用的 tag | 409 HAS_REFERENCES | |

---

## 第六層：RSS Feeds

| # | 測試 | 方法 | 預期結果 | ✅ |
|---|------|------|---------|---|
| 45 | List feeds | `/admin/feeds` | 顯示 14 個 seed feeds | |
| 46 | Toggle feed | Disable 一個 feed → 再 Enable | enabled 切換成功 | |
| 47 | Manual fetch | 對一個 feed 點 Fetch Now | 新的 collected items 出現 | |
| 48 | Collected list | `/admin/collected` | 顯示收集的文章（有 AI score） | |
| 49 | Feedback | 對 collected item 點 👍 或 👎 | feedback 記錄成功 | |
| 50 | Ignore | 對 collected item 點 Ignore | 狀態變 ignored | |

---

## 第七層：Spaced Repetition

| # | 測試 | 方法 | 預期結果 | ✅ |
|---|------|------|---------|---|
| 51 | Enroll | `/admin/spaced` → 加入複習 → 輸入 note ID | 成功 enroll | |
| 52 | Enroll duplicate | 再次 enroll 同一個 note ID | 409 已在複習系統中 | |
| 53 | List due | 頁面顯示到期卡片 | 至少 1 張（剛 enroll 的） | |
| 54 | Review | 翻牌 → 選 quality 5 | 顯示「下次複習：1 天後」 | |
| 55 | Skip | 點 Skip 按鈕 | 跳過，進下一張 | |
| 56 | Complete | 全部 review 完 | 顯示「本次複習完成！」 | |

---

## 第八層：Notion Sources

| # | 測試 | 方法 | 預期結果 | ✅ |
|---|------|------|---------|---|
| 57 | Discover | Create dialog → 呼叫 discover（如前端已整合） | 顯示 Notion databases dropdown | |
| 58 | Register source | 新增 Projects DB source | 成功建立 | |
| 59 | Register 4 sources | 依序新增 Projects/Tasks/Books/Goals | 4 筆 notion_sources | |
| 60 | Toggle source | 停用再啟用一個 source | enabled 切換 | |
| 61 | Edit source | 修改 description 或 poll_interval | 更新成功 | |
| 62 | Delete source | 刪除一個 source | 204 No Content | |

---

## 第九層：Activity & Analytics

| # | 測試 | 方法 | 預期結果 | ✅ |
|---|------|------|---------|---|
| 63 | Sessions | `/admin/activity` Tab 1 | 顯示 work sessions（需有足夠 events） | |
| 64 | Changelog | `/admin/activity` Tab 2 | 顯示每日事件時間線 | |
| 65 | Notion in changelog | 在 Notion 做操作 → 看 changelog | 出現 source: notion 的事件 | |
| 66 | Three sources | changelog 裡同時看到 github + obsidian + notion | 三源統一確認 | |

---

## 第十層：Flow Runs

| # | 測試 | 方法 | 預期結果 | ✅ |
|---|------|------|---------|---|
| 67 | List runs | `/admin/flow-runs` | 顯示 flow 執行歷史 | |
| 68 | Filter by status | 選 Failed filter | 只顯示失敗的 runs | |
| 69 | View detail | 展開一個 run | 顯示 Input/Output/Error JSON | |
| 70 | Retry | 對失敗的 run 點 Retry | status 變回 pending | |

---

## 第十一層：Review Queue

| # | 測試 | 方法 | 預期結果 | ✅ |
|---|------|------|---------|---|
| 71 | List reviews | `/admin/review` | 顯示待審項目（需先有 content-review flow 完成） | |
| 72 | Approve | 點 Approve | 內容 status → published | |
| 73 | Reject | 點 Reject → 輸入 notes → 確認 | 從 queue 移除 | |

---

## 第十二層：Cron Jobs（觀察 1-2 天）

| # | 測試 | 時間 | 驗證方法 | ✅ |
|---|------|------|---------|---|
| 74 | Morning Brief | 07:30 | LINE 收到早安簡報 | |
| 75 | Spaced reminder | 09:00 | LINE 收到複習提醒 + Notion 出現 reminder task | |
| 76 | Weekly Review | 週一 09:00 | LINE 收到週回顧 | |
| 77 | Build-log | 週一 10:00 | flow_runs 出現 build-log-generate | |
| 78 | Daily Dev Log | 23:00 | LINE 收到今日摘要 | |
| 79 | RSS daily collect | 06:00 | collected_data 有新資料 | |
| 80 | Hourly sync | :15 | Logs: SyncAllFromGitHub + SyncAll | |
| 81 | Token budget reset | 00:00 | Logs: daily token budget reset | |
| 82 | Token cleanup | 01:00 | Logs: expired tokens cleaned up | |
| 83 | Reconciliation | 週日 04:00 | Logs: reconciliation 執行 | |

---

## 第十三層：Public Pages

| # | 測試 | 方法 | 預期結果 | ✅ |
|---|------|------|---------|---|
| 84 | Home | `/` | Hero + Featured Projects + Tech Stack + Latest Feed | |
| 85 | Articles list | `/articles` | 文章列表 + 搜尋框 + 分頁 | |
| 86 | Article detail | `/articles/{slug}` | Markdown 渲染 + TOC + Related | |
| 87 | Projects list | `/projects` | 專案卡片 + 狀態篩選 | |
| 88 | Project detail | `/projects/{slug}` | Case study 版面 | |
| 89 | Build logs | `/build-logs` | Build log 列表 | |
| 90 | TILs | `/til` | TIL 列表 + tag filter | |
| 91 | Notes | `/notes` | 筆記列表 | |
| 92 | Tag page | `/tags/{tag}` | 按 tag 篩選內容 | |
| 93 | About | `/about` | 個人介紹 + 技能 + 聯絡方式 | |
| 94 | Uses | `/uses` | 工具清單 | |
| 95 | Search | `/search?q=test` | 搜尋結果 | |
| 96 | 404 | `/nonexistent-page` | 404 頁面 + 回首頁連結 | |

---

## 部署後一次性設定

| # | 設定 | 方法 | ✅ |
|---|------|------|---|
| S1 | 註冊 Notion Sources | `/admin/notion-sources` → 新增 4 個 DB (Projects/Tasks/Books/Goals) | |
| S2 | 設定 Project repo | `/admin/projects/{id}` → 編輯 → 填入 `repo` 欄位 (如 `Koopa0/blog`) | |
| S3 | 建立 Canonical Tags | `/admin/tags` → 新增常用 tags (go, rust, angular, kubernetes...) | |
| S4 | 觸發首次 RSS Collect | Dashboard → RSS Collect 按鈕 | |
| S5 | 觸發首次 Obsidian Sync | Dashboard → Obsidian Sync 按鈕 | |
| S6 | 觸發首次 Notion Sync | Dashboard → Notion Sync 按鈕 | |

---

## 備註

- 第二層（Webhook）是最關鍵的 — 確認三源 data flow
- 第十二層（Cron）需要 1-2 天觀察
- 如果第七層 content-review flow 失敗，檢查 token budget 和 API key
- 測試順序：1→5 → 6→15 → 16→24 → S1→S6 → 其他隨意
