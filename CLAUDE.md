# koopa0.dev — 個人知識引擎平台

> 這不是一個部落格。這是一個可輸入、可輸出的個人知識系統。

## Monorepo 結構

```
/Users/koopa/blog/
├── frontend/     # Angular 21 前端（SSR + Tailwind v4）
├── backend/      # Go API + AI Pipeline（Koopa 開發中）
├── docs/         # 共用設計文件
│   └── PLATFORM-VISION.md  ← 完整平台設計（必讀）
├── CLAUDE.md     # 你現在在讀的這份
└── .gitignore
```

## 必讀文件

| 文件 | 用途 |
|------|------|
| `docs/PLATFORM-VISION.md` | **完整平台設計** — 系統架構、API spec、資料模型、執行階段 |
| `frontend/CLAUDE.md` | Angular 前端開發規範（元件、規則、命名、測試） |
| `backend/CLAUDE.md` | Go 後端開發規範（Koopa 維護） |

## 平台三大面向

1. **輸入** — Obsidian 知識庫同步、外部資料主動收集（RSS/API/爬蟲）
2. **處理** — Go Genkit AI Pipeline：整理、分類、生成草稿、審核分級
3. **輸出** — Angular SSR 網站：主題式內容呈現、個人品牌展示

## 技術棧

| 層 | 技術 |
|----|------|
| 前端 | Angular 21, Tailwind CSS v4, SSR |
| 後端 | Go, Genkit, PostgreSQL |
| AI | Genkit Flow, Prompt 模板 |
| 部署 | Docker, VPS |

## 核心設計原則

- **Obsidian-first** — 內容源頭是 Obsidian，網站是呈現層
- **AI 輔助，人類把關** — 審核分級制（自動/輕度/標準/嚴格）
- **主題驅動** — 內容按 Topic 組織，格式次要
- **用作品說話** — 不列學經歷，讓作品和內容展示能力
- **對自己有用** — 首先是知識管理工具，其次是對外展示

## 內容類型

| 類型 | 說明 |
|------|------|
| `article` | 深度技術文章 |
| `essay` | 個人想法、非技術反思 |
| `build-log` | 專案開發紀錄 |
| `til` | 每日學習（短） |
| `note` | 技術筆記片段 |
| `bookmark` | 推薦資源 + 個人評語 |
| `digest` | 週報/月報 |

## 開發分工

| 負責人 | 範圍 |
|--------|------|
| Koopa | Go API、AI Pipeline、Obsidian 整合、資料收集 |
| Claude Code | Angular 前端、API 對接、Admin UI、設計調整 |

## 語言規範

- 文件和 UI 文字：繁體中文
- 程式碼（變數、函式）：English
- Git commits：English (Conventional Commits)
