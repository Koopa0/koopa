import { APP_BASE_HREF } from '@angular/common';
import { CommonEngine, createNodeRequestHandler, isMainModule } from '@angular/ssr/node';
import express from 'express';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import bootstrap from './src/main.server';

const serverDistFolder = dirname(fileURLToPath(import.meta.url));
const browserDistFolder = resolve(serverDistFolder, '../browser');
const indexHtml = join(serverDistFolder, 'index.server.html');

const SITE_URL = process.env['SITE_URL'] || 'https://koopa0.dev';
const SITE_TITLE = 'koopa0.dev';
const SITE_DESCRIPTION =
  'Backend Engineer / Full-Stack Developer - 技術文章與個人作品集';

const app = express();
app.disable('x-powered-by');
const commonEngine = new CommonEngine();

// Security headers
app.use((_req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// security.txt (RFC 9116)
app.get('/.well-known/security.txt', (_req, res) => {
  res.type('text/plain').send(
    `Contact: mailto:contact@koopa0.dev\nPreferred-Languages: zh-TW, en\nCanonical: https://koopa0.dev/.well-known/security.txt\nExpires: 2027-01-01T00:00:00.000Z\n`,
  );
});

// 靜態頁面路由（用於 sitemap）
const STATIC_ROUTES: Array<{
  path: string;
  changefreq: string;
  priority: string;
}> = [
  { path: '/', changefreq: 'daily', priority: '1.0' },
  { path: '/home', changefreq: 'daily', priority: '1.0' },
  { path: '/articles', changefreq: 'daily', priority: '0.9' },
  { path: '/projects', changefreq: 'weekly', priority: '0.8' },
  { path: '/build-logs', changefreq: 'weekly', priority: '0.7' },
  { path: '/til', changefreq: 'daily', priority: '0.7' },
  { path: '/notes', changefreq: 'weekly', priority: '0.6' },
  { path: '/resume', changefreq: 'monthly', priority: '0.7' },
  { path: '/uses', changefreq: 'monthly', priority: '0.5' },
  { path: '/about', changefreq: 'monthly', priority: '0.7' },
];

// 內容資料（從 mock 同步；未來接 API 後改為動態取得）
interface FeedItem {
  title: string;
  path: string;
  excerpt: string;
  tags: string[];
  publishedAt: string;
}

interface ArticleFeedItem {
  id: string;
  title: string;
  slug: string;
  excerpt: string;
  tags: string[];
  publishedAt: string;
}

function getArticles(): ArticleFeedItem[] {
  // 此清單與 mock-data.ts 同步；未來改為從資料庫/CMS 取得
  return [
    {
      id: '1',
      title: 'Angular Signals: 完整指南與最佳實踐',
      slug: 'angular-signals-complete-guide',
      excerpt:
        '深入探討 Angular 20+ 中的 Signal 響應式編程，包含實戰範例和效能優化技巧。',
      tags: ['Angular', 'TypeScript', 'Web Development'],
      publishedAt: '2024-12-01T00:00:00+08:00',
    },
    {
      id: '2',
      title: 'Golang 併發編程：Goroutines 與 Channels 深度解析',
      slug: 'golang-concurrency-goroutines-channels',
      excerpt:
        '探索 Go 語言強大的併發模型，從 goroutines 的基本概念到 channels 的高級用法。',
      tags: ['Golang'],
      publishedAt: '2024-11-28T00:00:00+08:00',
    },
    {
      id: '3',
      title: 'Rust 所有權系統：記憶體安全的革命性方法',
      slug: 'rust-ownership-memory-safety',
      excerpt:
        'Rust 的所有權系統如何在不使用垃圾回收器的情況下保證記憶體安全？',
      tags: ['Rust'],
      publishedAt: '2024-11-25T00:00:00+08:00',
    },
    {
      id: '4',
      title: 'Flutter 狀態管理：Riverpod vs Bloc 完整比較',
      slug: 'flutter-state-management-riverpod-bloc',
      excerpt:
        '深度比較 Flutter 兩大主流狀態管理方案：Riverpod 和 Bloc。',
      tags: ['Flutter'],
      publishedAt: '2024-11-22T00:00:00+08:00',
    },
    {
      id: '5',
      title: 'PostgreSQL 效能優化：索引策略與查詢調優',
      slug: 'postgresql-performance-optimization',
      excerpt:
        'PostgreSQL 效能優化的完整指南，包含索引設計、查詢分析、配置調優等實戰技巧。',
      tags: ['PostgreSQL'],
      publishedAt: '2024-11-20T00:00:00+08:00',
    },
    {
      id: '6',
      title: 'AI 輔助程式開發：ChatGPT 與 GitHub Copilot 實戰指南',
      slug: 'ai-assisted-programming-guide',
      excerpt:
        'AI 工具如何革命性地改變程式開發流程？深入探討 AI 工具的實際應用技巧。',
      tags: ['AI', 'Web Development'],
      publishedAt: '2024-11-18T00:00:00+08:00',
    },
  ];
}

function getBuildLogs(): FeedItem[] {
  return [
    {
      title: 'koopa0.dev 部落格建置紀錄 #1',
      path: '/build-logs/koopa-blog-build-log-1',
      excerpt: '從零開始打造個人部落格 — Angular 21 + SSR + Tailwind CSS v4 的技術選型與架構設計。',
      tags: ['Angular', 'SSR'],
      publishedAt: '2024-12-05T00:00:00+08:00',
    },
    {
      title: 'Resonance 專案啟動紀錄',
      path: '/build-logs/resonance-kickoff',
      excerpt: 'AI 文學共創平台 Resonance 的設計理念與技術規劃。',
      tags: ['Go', 'Angular', 'AI'],
      publishedAt: '2024-12-03T00:00:00+08:00',
    },
  ];
}

function getTils(): FeedItem[] {
  return [
    {
      title: 'Go Dockerfile Multi-stage Build',
      path: '/til/go-dockerfile-multistage',
      excerpt: '使用 multi-stage build 優化 Go 專案的 Docker 映像大小。',
      tags: ['Golang', 'Docker'],
      publishedAt: '2024-12-06T00:00:00+08:00',
    },
    {
      title: 'Angular linkedSignal 用法',
      path: '/til/angular-linked-signal',
      excerpt: 'Angular 21 linkedSignal 的使用情境與範例。',
      tags: ['Angular', 'TypeScript'],
      publishedAt: '2024-12-04T00:00:00+08:00',
    },
  ];
}

function escapeXml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// Sitemap XML — 包含靜態頁面 + 所有已發布文章
app.get('/sitemap.xml', (_req, res) => {
  const now = new Date().toISOString().split('T')[0];
  const articles = getArticles();

  const staticUrls = STATIC_ROUTES.map(
    (route) =>
      `  <url>
    <loc>${SITE_URL}${route.path}</loc>
    <lastmod>${now}</lastmod>
    <changefreq>${route.changefreq}</changefreq>
    <priority>${route.priority}</priority>
  </url>`,
  );

  const articleUrls = articles.map(
    (article) =>
      `  <url>
    <loc>${SITE_URL}/articles/${article.id}</loc>
    <lastmod>${article.publishedAt.split('T')[0]}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>`,
  );

  const buildLogUrls = getBuildLogs().map(
    (bl) =>
      `  <url>
    <loc>${SITE_URL}${bl.path}</loc>
    <lastmod>${bl.publishedAt.split('T')[0]}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>`,
  );

  const tilUrls = getTils().map(
    (til) =>
      `  <url>
    <loc>${SITE_URL}${til.path}</loc>
    <lastmod>${til.publishedAt.split('T')[0]}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.4</priority>
  </url>`,
  );

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${[...staticUrls, ...articleUrls, ...buildLogUrls, ...tilUrls].join('\n')}
</urlset>`;

  res.set('Content-Type', 'application/xml');
  res.set('Cache-Control', 'public, max-age=3600');
  res.send(xml);
});

// RSS Feed — 包含所有已發布內容（文章 + Build Log + TIL）
app.get('/feed.xml', (_req, res) => {
  const articles = getArticles();
  const buildLogs = getBuildLogs();
  const tils = getTils();

  const allItems: FeedItem[] = [
    ...articles.map((a) => ({
      title: a.title,
      path: `/articles/${a.id}`,
      excerpt: a.excerpt,
      tags: a.tags,
      publishedAt: a.publishedAt,
    })),
    ...buildLogs,
    ...tils,
  ].sort(
    (a, b) =>
      new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime(),
  );

  const latestDate = allItems.length > 0
    ? new Date(allItems[0].publishedAt).toUTCString()
    : new Date().toUTCString();

  const items = allItems
    .map(
      (item) => `    <item>
      <title>${escapeXml(item.title)}</title>
      <link>${SITE_URL}${item.path}</link>
      <guid isPermaLink="true">${SITE_URL}${item.path}</guid>
      <description>${escapeXml(item.excerpt)}</description>
      <pubDate>${new Date(item.publishedAt).toUTCString()}</pubDate>
${item.tags.map((tag) => `      <category>${escapeXml(tag)}</category>`).join('\n')}
    </item>`,
    )
    .join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${escapeXml(SITE_TITLE)}</title>
    <description>${escapeXml(SITE_DESCRIPTION)}</description>
    <link>${SITE_URL}</link>
    <atom:link href="${SITE_URL}/feed.xml" rel="self" type="application/rss+xml" />
    <language>zh-TW</language>
    <lastBuildDate>${latestDate}</lastBuildDate>
    <generator>Angular SSR</generator>
${items}
  </channel>
</rss>`;

  res.set('Content-Type', 'application/rss+xml');
  res.set('Cache-Control', 'public, max-age=3600');
  res.send(xml);
});

// 健康檢查端點（部署用）
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// BFF Proxy — 轉發 /bff/* 到後端，後端零暴露
const BACKEND_URL = process.env['BACKEND_URL'] || 'http://backend:8080';

app.use('/bff', (req, res) => {
  const targetUrl = `${BACKEND_URL}${req.originalUrl.replace(/^\/bff/, '')}`;
  const headers: Record<string, string> = {
    'content-type': req.headers['content-type'] || 'application/json',
  };
  if (req.headers['authorization']) {
    headers['authorization'] = req.headers['authorization'] as string;
  }
  if (req.headers['cookie']) {
    headers['cookie'] = req.headers['cookie'] as string;
  }

  const bodyChunks: Buffer[] = [];
  req.on('data', (chunk: Buffer) => bodyChunks.push(chunk));
  req.on('end', () => {
    const body = bodyChunks.length > 0 ? Buffer.concat(bodyChunks) : undefined;
    fetch(targetUrl, {
      method: req.method,
      headers,
      body,
    })
      .then(async (upstream) => {
        res.status(upstream.status);
        upstream.headers.forEach((value, key) => {
          if (!['transfer-encoding', 'content-encoding'].includes(key.toLowerCase())) {
            res.setHeader(key, value);
          }
        });
        const data = await upstream.arrayBuffer();
        res.send(Buffer.from(data));
      })
      .catch((err) => {
        console.error('BFF proxy error:', err);
        res.status(502).json({ error: 'Backend unavailable' });
      });
  });
});

app.use(
  express.static(browserDistFolder, {
    maxAge: '1y',
    index: false,
    redirect: false,
  }),
);

app.use((req, res, next) => {
  commonEngine
    .render({
      bootstrap,
      documentFilePath: indexHtml,
      url: `${req.protocol}://${req.headers.host}${req.originalUrl}`,
      publicPath: browserDistFolder,
      providers: [{ provide: APP_BASE_HREF, useValue: req.baseUrl }],
    })
    .then((html) => res.send(html))
    .catch(next);
});

if (isMainModule(import.meta.url)) {
  const port = process.env['PORT'] || 4000;
  app.listen(port, () => {
    console.log(`Node Express server listening on http://localhost:${port}`);
  });
}

export default createNodeRequestHandler(app);
