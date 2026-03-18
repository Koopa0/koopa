# koopa0.dev Frontend ↔ Backend API 對接指南

> **Date**: 2026-03-18
> **Backend Version**: Phase 1-4 complete (31/35)
> **Frontend**: Angular 21 + SSR + Tailwind v4
> **BFF Proxy**: `/bff/*` → `http://backend:8080/api/*`

---

## 一、通訊規範

### 基本規則

| 項目 | 規則 |
|------|------|
| Base URL | `/bff` (SSR server proxy to backend) |
| Content-Type | `application/json` |
| Auth Header | `Authorization: Bearer <access_token>` (admin routes only) |
| 分頁 | `?page=1&per_page=20` (max 100) |
| Error Format | `{ "error": { "code": "NOT_FOUND", "message": "..." } }` |
| Response Format | `{ "data": T }` or `{ "data": T[], "meta": { total, page, per_page, total_pages } }` |

### Auth Flow

```
1. GET /bff/auth/google → redirect to Google OAuth
2. Google callback → redirect to frontend with #access_token=...&refresh_token=...
3. Frontend stores tokens in memory (NOT localStorage)
4. Frontend calls history.replaceState to clear URL fragment
5. When access_token expires → POST /bff/auth/refresh { "refresh_token": "..." }
6. Access token: 24h | Refresh token: 7d
```

### Error Codes

| Code | HTTP Status | 說明 |
|------|-------------|------|
| `BAD_REQUEST` | 400 | 無效的 request body 或參數 |
| `UNAUTHORIZED` | 401 | JWT 無效或過期 |
| `FORBIDDEN` | 403 | 沒有權限 |
| `NOT_FOUND` | 404 | 資源不存在 |
| `CONFLICT` | 409 | 唯一性衝突 (slug/email already exists) |
| `HAS_REFERENCES` | 409 | 無法刪除 (有 alias/notes 引用) |
| `INTERNAL` | 500 | 伺服器內部錯誤 |

---

## 二、新增 Admin 頁面需求 (後端已就緒，待前端實作)

### 2.1 Tag 管理頁面 (`/admin/tags`)

**Backend 已完成**: 11 個 endpoints，`api.model.ts` 已有 `ApiTag` + `ApiTagAlias` types。

#### Tab 1: Canonical Tags

| 操作 | Endpoint | 說明 |
|------|----------|------|
| 列表 | `GET /bff/admin/tags` | 回傳所有 canonical tags |
| 新增 | `POST /bff/admin/tags` | `{ slug, name, parent_id?, description? }` |
| 編輯 | `PUT /bff/admin/tags/{id}` | partial update |
| 刪除 | `DELETE /bff/admin/tags/{id}` | 有引用時回 409 `HAS_REFERENCES` |
| 合併 | `POST /bff/admin/tags/merge` | `{ source_id, target_id }` → 合併重複 tag |
| 回填 | `POST /bff/admin/tags/backfill` | 掃描所有筆記 raw tags → 補寫 junction table |

**合併回應**:
```typescript
interface MergeResult {
  aliases_moved: number;
  notes_moved: number;
  events_moved: number;
}
```

**回填回應**:
```typescript
interface BackfillResult {
  notes_processed: number;
  tags_mapped: number;
  tags_unmapped: number;
}
```

#### Tab 2: Tag Aliases

| 操作 | Endpoint | 說明 |
|------|----------|------|
| 列表 (全部) | `GET /bff/admin/aliases` | 所有 aliases |
| 列表 (未映射) | `GET /bff/admin/aliases?unmapped=true` | 待整理的 raw tags |
| 映射 | `POST /bff/admin/aliases/{id}/map` | `{ tag_id: "uuid" }` |
| 確認 | `POST /bff/admin/aliases/{id}/confirm` | 確認自動映射 |
| 拒絕 | `POST /bff/admin/aliases/{id}/reject` | 拒絕不需要的 tag |
| 刪除 | `DELETE /bff/admin/aliases/{id}` | 204 No Content |

---

### 2.2 Notion Source 管理頁面 (`/admin/notion-sources`)

**Backend 已完成**: 6 個 endpoints。需要新增 TypeScript types。

```typescript
// 新增到 api.model.ts
interface ApiNotionSource {
  id: string;
  database_id: string;
  name: string;
  description: string;
  sync_mode: 'full' | 'events';
  property_map: Record<string, unknown>;
  poll_interval: string; // "5 minutes" | "15 minutes" | "1 hour" | ...
  enabled: boolean;
  last_synced_at: string | null;
  created_at: string;
  updated_at: string;
}

interface ApiCreateNotionSourceRequest {
  database_id: string;  // Notion database ID (required, max 255)
  name: string;         // Display name (required, max 255)
  description?: string;
  sync_mode?: 'full' | 'events'; // default: 'full'
  property_map?: Record<string, unknown>; // max 64 KB JSON
  poll_interval?: string; // default: '15 minutes', allowlist values
}

interface ApiUpdateNotionSourceRequest {
  name?: string;
  description?: string;
  sync_mode?: 'full' | 'events';
  property_map?: Record<string, unknown>;
  poll_interval?: string;
  enabled?: boolean;
}
```

| 操作 | Endpoint | 說明 |
|------|----------|------|
| 列表 | `GET /bff/admin/notion-sources` | 所有註冊的 Notion databases |
| 取得 | `GET /bff/admin/notion-sources/{id}` | 單筆 |
| 新增 | `POST /bff/admin/notion-sources` | 註冊新 database |
| 更新 | `PUT /bff/admin/notion-sources/{id}` | 修改設定 |
| 刪除 | `DELETE /bff/admin/notion-sources/{id}` | 移除 (404 if not found) |
| 切換 | `POST /bff/admin/notion-sources/{id}/toggle` | 啟用/停用 |

**poll_interval 允許的值**: `"5 minutes"`, `"10 minutes"`, `"15 minutes"`, `"30 minutes"`, `"1 hour"`, `"2 hours"`, `"4 hours"`, `"6 hours"`, `"12 hours"`, `"24 hours"`

---

### 2.3 Spaced Repetition 頁面 (`/admin/spaced`)

**Backend 已完成**: 3 個 endpoints + LINE 通知。

```typescript
// 新增到 api.model.ts
interface ApiSpacedInterval {
  note_id: number;
  file_path: string;
  title: string | null;
  type: string | null;
  easiness_factor: number;
  interval_days: number;
  repetitions: number;
  last_quality: number | null;
  due_at: string;
  reviewed_at: string | null;
}

interface ApiSubmitReviewRequest {
  note_id: number;  // obsidian_notes.id
  quality: number;  // 0-5 (SM-2 quality rating)
}

interface ApiEnrollRequest {
  note_id: number;  // obsidian_notes.id
}
```

| 操作 | Endpoint | 說明 |
|------|----------|------|
| 到期列表 | `GET /bff/admin/spaced/due?limit=50` | 到期需要複習的筆記 (max 100) |
| 提交複習 | `POST /bff/admin/spaced/review` | `{ note_id, quality }` → 回傳更新後的 interval |
| 加入複習 | `POST /bff/admin/spaced/enroll` | `{ note_id }` → 409 if already enrolled |

**SM-2 Quality 說明** (顯示在 UI):
| Quality | 含義 | 建議 UI |
|---------|------|--------|
| 0 | 完全不記得 | 😵 |
| 1 | 答錯，看到答案才想起 | 😟 |
| 2 | 答錯，但覺得快想起來了 | 😐 |
| 3 | 正確但很費力 | 🤔 |
| 4 | 正確，稍有猶豫 | 😊 |
| 5 | 完美，立刻回答 | 🎯 |

---

### 2.4 Dashboard 統計頁面 (`/admin/dashboard`)

**Backend 已完成**: 3 個 stats endpoints。

```typescript
// 新增到 api.model.ts
interface ApiStatsOverview {
  contents: { total: number; by_status: Record<string, number>; by_type: Record<string, number>; published: number };
  collected: { total: number; by_status: Record<string, number> };
  feeds: { total: number; enabled: number };
  flow_runs: { total: number; by_status: Record<string, number> };
  projects: { total: number; by_status: Record<string, number> };
  reviews: { pending: number; total: number };
  notes: { total: number; by_type: Record<string, number> };
  activity: { total: number; last_24h: number; last_7d: number; by_source: Record<string, number> };
  spaced: { enrolled: number; due: number };
  sources: { total: number; enabled: number };
  tags: { canonical: number; aliases: number; unconfirmed: number };
}

interface ApiDriftReport {
  period: string; // "last 30 days"
  areas: Array<{
    area: string;
    active_goals: number;
    event_count: number;
    event_percent: number;
    goal_percent: number;
    drift_percent: number; // positive = over-investing, negative = under-investing
  }>;
}

interface ApiLearningDashboard {
  spaced: { enrolled: number; due: number };
  notes: { total: number; last_week: number; last_month: number; by_type: Record<string, number> };
  activity: { this_week: number; last_week: number; trend: 'up' | 'down' | 'stable' };
  top_tags: Array<{ name: string; count: number }>;
}
```

| Endpoint | 用途 | 建議 UI 位置 |
|----------|------|-------------|
| `GET /bff/admin/stats` | 平台總覽 (11 指標) | Dashboard 首頁 cards |
| `GET /bff/admin/stats/drift?days=30` | 精力偏差分析 | Dashboard 圖表 (bar chart: goal% vs event%) |
| `GET /bff/admin/stats/learning` | 學習追蹤 | Dashboard 或獨立 Learning 頁 |

---

### 2.5 Activity 頁面 (`/admin/activity`)

```typescript
// 新增到 api.model.ts
interface ApiSession {
  start: string;
  end: string;
  duration: string; // "1h30m0s"
  event_count: number;
  sources: string[];
  projects: string[];
}

interface ApiChangelogDay {
  date: string; // "2026-03-18"
  event_count: number;
  events: Array<{
    source: string;
    event_type: string;
    project: string | null;
    title: string | null;
    timestamp: string;
  }>;
}
```

| Endpoint | 用途 | 建議 UI |
|----------|------|--------|
| `GET /bff/admin/activity/sessions?days=7` | 工作 sessions (30min gap) | 時間軸視覺化 |
| `GET /bff/admin/activity/changelog?days=30` | 每日活動時間線 | 日曆 heatmap + 展開 |

---

## 三、現有頁面需要的 API 更新

### 3.1 已有 Angular 頁面 ↔ 後端對照

| 前端頁面 | 後端 API | 狀態 |
|----------|----------|------|
| `/admin/dashboard` | `GET /bff/admin/stats` | ⚠️ 前端可能還在用舊的 hardcoded response |
| `/admin/contents` | CRUD endpoints | ✅ 已對接 |
| `/admin/projects` | CRUD endpoints | ✅ 已對接 |
| `/admin/review` | List/Approve/Reject/Edit | ✅ 已對接 |
| `/admin/collected` | List/Curate/Ignore/Feedback | ✅ 已對接 |
| `/admin/feeds` | CRUD + Fetch | ✅ 已對接 |
| `/admin/flow-runs` | List/ByID/Retry | ✅ 已對接 |
| `/admin/tracking` | CRUD | ✅ 已對接 |
| `/admin/upload` | POST multipart | ✅ 已對接 |
| `/admin/tags` | **11 endpoints** | ⚠️ **後端就緒，待前端實作** |
| `/admin/notion-sources` | **6 endpoints** | 🆕 **新頁面** |
| `/admin/spaced` | **3 endpoints** | 🆕 **新頁面** |
| `/admin/activity` | **2 endpoints** | 🆕 **新頁面** |

### 3.2 Public 頁面

所有公開 API 已就緒。無新增需求。

---

## 四、Pipeline Endpoints (Admin 觸發)

| Endpoint | 用途 | UI 建議 |
|----------|------|--------|
| `POST /bff/pipeline/sync` | 手動觸發 GitHub Obsidian sync | Pipeline 管理頁按鈕 |
| `POST /bff/pipeline/notion-sync` | 手動觸發 Notion full sync | Pipeline 管理頁按鈕 |
| `POST /bff/pipeline/reconcile` | 手動觸發 Obsidian↔Notion 比對 | Pipeline 管理頁按鈕 |
| `POST /bff/pipeline/collect` | 手動觸發 RSS feed 收集 | Feeds 頁按鈕 |
| `POST /bff/pipeline/digest` | 手動生成 digest | Content creation |
| `POST /bff/pipeline/bookmark` | 手動生成 bookmark | Collected data curation |

### Flow Polish (Admin)

| Endpoint | 用途 |
|----------|------|
| `POST /bff/admin/flow/polish/{content_id}` | 觸發 Claude 潤稿 |
| `GET /bff/admin/flow/polish/{content_id}/result` | 取得潤稿結果 (diff) |
| `POST /bff/admin/flow/polish/{content_id}/approve` | 批准潤稿結果 |

---

## 五、前端開發優先順序建議

| Priority | 頁面 | 複雜度 | 說明 |
|----------|------|--------|------|
| 🔴 P0 | `/admin/tags` | 中 | 2 tabs (Tags + Aliases), merge/backfill 操作 |
| 🔴 P0 | `/admin/dashboard` 更新 | 低 | 接 `GET /bff/admin/stats` 替換 hardcoded data |
| 🟡 P1 | `/admin/spaced` | 中 | Card-based review UI, quality rating buttons |
| 🟡 P1 | `/admin/notion-sources` | 低 | 標準 CRUD table + toggle switch |
| 🟢 P2 | `/admin/activity` | 中 | Sessions timeline + changelog calendar |
| 🟢 P2 | `/admin/stats/drift` | 中 | Bar chart (goal% vs event%) |
| 🟢 P2 | `/admin/stats/learning` | 低 | Stats cards + trend indicator |

---

## 六、TypeScript Types 待新增清單

以下 types 需要加到 `frontend/src/app/core/models/api.model.ts`:

```typescript
// === Notion Sources ===
export interface ApiNotionSource { ... } // 見 §2.2
export interface ApiCreateNotionSourceRequest { ... }
export interface ApiUpdateNotionSourceRequest { ... }

// === Spaced Repetition ===
export interface ApiSpacedInterval { ... } // 見 §2.3
export interface ApiSubmitReviewRequest { ... }
export interface ApiEnrollRequest { ... }

// === Stats ===
export interface ApiStatsOverview { ... } // 見 §2.4
export interface ApiDriftReport { ... }
export interface ApiLearningDashboard { ... }

// === Activity ===
export interface ApiSession { ... } // 見 §2.5
export interface ApiChangelogDay { ... }

// === Tag Operations ===
export interface ApiMergeTagsRequest { source_id: string; target_id: string; }
export interface ApiMergeResult { aliases_moved: number; notes_moved: number; events_moved: number; }
export interface ApiBackfillResult { notes_processed: number; tags_mapped: number; tags_unmapped: number; }
```
