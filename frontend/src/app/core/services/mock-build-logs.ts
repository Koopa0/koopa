import { BuildLog } from '../models/build-log.model';

export const MOCK_BUILD_LOGS: BuildLog[] = [
  {
    id: 'bl-001',
    slug: 'blog-ssr-implementation',
    projectId: 'proj-001',
    title: '為 Blog 加入 SSR：從零開始的伺服器端渲染',
    excerpt:
      '記錄將 Angular Blog 從 CSR 遷移到 SSR 的完整過程，包含 Express 設定、路由策略選擇和效能比較。',
    content: '',
    tags: ['Angular', 'TypeScript', 'Web Development'],
    publishedAt: new Date('2024-11-30'),
    updatedAt: new Date('2024-11-30'),
    readingTime: 8,
    status: 'published',
  },
  {
    id: 'bl-002',
    slug: 'blog-dark-mode-system',
    projectId: 'proj-001',
    title: '深色模式的設計與實作：不只是換顏色',
    excerpt:
      '如何設計一個完整的主題系統？從 ThemeService 到 Tailwind dark: prefix，以及踩過的坑。',
    content: '',
    tags: ['Angular', 'TypeScript'],
    publishedAt: new Date('2024-11-26'),
    updatedAt: new Date('2024-11-26'),
    readingTime: 6,
    status: 'published',
  },
  {
    id: 'bl-003',
    slug: 'api-gateway-rate-limiting',
    projectId: 'proj-002',
    title: 'Redis Rate Limiting 的三種實作方式比較',
    excerpt:
      '在 API Gateway 專案中嘗試了 Fixed Window、Sliding Window 和 Token Bucket 三種限流演算法的實作與效能比較。',
    content: '',
    tags: ['Golang', 'PostgreSQL'],
    publishedAt: new Date('2024-11-20'),
    updatedAt: new Date('2024-11-20'),
    readingTime: 10,
    status: 'published',
  },
  {
    id: 'bl-004',
    slug: 'task-tracker-sqlite-migration',
    projectId: 'proj-003',
    title: 'Rust + SQLite：從 JSON 檔案遷移到關聯式資料庫',
    excerpt:
      '原本用 JSON 檔案存資料，隨著功能增加決定遷移到 SQLite。記錄遷移過程和 Rust SQLite 生態的選擇。',
    content: '',
    tags: ['Rust'],
    publishedAt: new Date('2024-11-15'),
    updatedAt: new Date('2024-11-15'),
    readingTime: 7,
    status: 'published',
  },
];
