import { Project } from '../models/project.model';

export const MOCK_PROJECTS: Project[] = [
  {
    id: 'proj-001',
    slug: 'koopa-blog',
    title: 'koopa0.dev',
    description:
      '個人技術部落格與作品集網站，使用 Angular 20 + Tailwind CSS v4 + SSR 建構',
    longDescription:
      '從零開始設計的個人網站，涵蓋部落格文章管理、SEO 最佳化、SSR 伺服器端渲染，並使用 Tailwind CSS v4 實現現代化 UI 設計。',
    techStack: ['Angular', 'TypeScript', 'Tailwind CSS', 'SSR', 'Express'],
    role: 'Full-Stack Developer',
    highlights: [
      'Angular 20 + Standalone Components + Signals',
      'Tailwind CSS v4 + Dark Mode',
      'Server-Side Rendering (SSR)',
      'SEO 最佳化 + JSON-LD 結構化資料',
      'Markdown 文章編輯器',
    ],
    githubUrl: 'https://github.com/koopa0/blog',
    liveUrl: 'https://koopa0.dev',
    featured: true,
    order: 1,
    status: 'maintained',
    problem:
      '需要一個兼具技術部落格、作品集展示和個人品牌的網站，但市面上的部落格平台缺乏客製化能力，靜態網站生成器又難以實現動態功能。',
    solution:
      '使用 Angular 21 從零建構，搭配 SSR 確保 SEO 表現，Tailwind CSS v4 實現快速 UI 開發，並建立完整的 Admin 後台管理系統。',
    architecture:
      'Angular SSR + Express 伺服器端渲染、Standalone Components + Signals 響應式架構、Markdown 渲染引擎搭配 highlight.js 語法高亮。',
    results:
      'Lighthouse Performance 95+、完整的 SEO meta tags + JSON-LD、支援深色/淺色模式切換、動態 RSS Feed 和 Sitemap 生成。',
    buildLogIds: ['bl-001', 'bl-002'],
  },
  {
    id: 'proj-002',
    slug: 'api-gateway',
    title: 'API Gateway Service',
    description:
      '高效能 API Gateway，使用 Golang 建構，支援限流、認證與路由轉發',
    techStack: ['Go', 'Redis', 'Docker', 'gRPC', 'PostgreSQL'],
    role: 'Backend Engineer',
    highlights: [
      'Go + net/http 高效能路由',
      'Redis-based rate limiting',
      'JWT 認證與 RBAC 授權',
      'gRPC 微服務串接',
      'Docker 容器化部署',
    ],
    githubUrl: 'https://github.com/koopa0/api-gateway',
    featured: true,
    order: 2,
    status: 'completed',
    problem:
      '微服務架構中各服務直接暴露會造成安全風險、缺乏統一的限流和認證機制，且難以監控跨服務的請求。',
    solution:
      '用 Go 建構輕量級 API Gateway，整合 JWT 認證、Redis 限流和 gRPC 轉發，作為所有外部請求的統一入口。',
    buildLogIds: ['bl-003'],
  },
  {
    id: 'proj-003',
    slug: 'task-tracker',
    title: 'Task Tracker CLI',
    description: '命令列任務管理工具，使用 Rust 建構，支援優先排序與時間追蹤',
    techStack: ['Rust', 'SQLite', 'clap', 'serde'],
    role: 'Developer',
    highlights: [
      'Rust CLI 應用程式',
      'SQLite 本地資料庫',
      '優先排序與篩選功能',
      '時間追蹤與統計報告',
    ],
    githubUrl: 'https://github.com/koopa0/task-tracker',
    featured: true,
    order: 3,
    status: 'completed',
  },
];
