import {
  AngularNodeAppEngine,
  createNodeRequestHandler,
  isMainModule,
  writeResponseToNodeResponse,
} from '@angular/ssr/node';
import express from 'express';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const serverDistFolder = dirname(fileURLToPath(import.meta.url));
const browserDistFolder = resolve(serverDistFolder, '../browser');

const SITE_URL = process.env['SITE_URL'] || 'https://koopa0.dev';
const SITE_TITLE = 'koopa0.dev';
const SITE_DESCRIPTION =
  'Software Engineer - Technical articles and personal projects';

const BACKEND_URL = process.env['BACKEND_URL'] || 'http://backend:8080';

const angularApp = new AngularNodeAppEngine();
const app = express();
app.disable('x-powered-by');

// Reject malformed URLs early (e.g. %c0 from scanners)
app.use((req, res, next) => {
  try {
    decodeURIComponent(req.originalUrl);
    next();
  } catch {
    res.status(400).end('Bad Request');
  }
});

// Security headers
app.use((_req, res, next) => {
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains',
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()',
  );
  next();
});

// security.txt (RFC 9116)
app.get('/.well-known/security.txt', (_req, res) => {
  res
    .type('text/plain')
    .send(
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
  { path: '/articles', changefreq: 'daily', priority: '0.9' },
  { path: '/projects', changefreq: 'weekly', priority: '0.8' },
  { path: '/til', changefreq: 'daily', priority: '0.7' },
  { path: '/notes', changefreq: 'weekly', priority: '0.6' },
  { path: '/resume', changefreq: 'monthly', priority: '0.7' },
  { path: '/uses', changefreq: 'monthly', priority: '0.5' },
  { path: '/about', changefreq: 'monthly', priority: '0.7' },
];

// 從後端 API 動態取得已發布內容（用於 sitemap + RSS feed）
interface ContentItem {
  slug: string;
  title: string;
  excerpt: string;
  type: string;
  tags: string[];
  published_at: string | null;
  updated_at: string;
}

interface ApiListResponse {
  data: ContentItem[];
  meta: { total: number; page: number; per_page: number; total_pages: number };
}

const TYPE_ROUTE_PREFIX: Record<string, string> = {
  article: '/articles',
  essay: '/essays',
  til: '/til',
  note: '/notes',
};

/** 從後端取得所有已發布內容，帶快取避免頻繁請求 */
let contentCache: { items: ContentItem[]; fetchedAt: number } | null = null;
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 分鐘

async function fetchPublishedContent(): Promise<ContentItem[]> {
  if (contentCache && Date.now() - contentCache.fetchedAt < CACHE_TTL_MS) {
    return contentCache.items;
  }

  try {
    const allItems: ContentItem[] = [];
    let page = 1;
    let totalPages = 1;

    while (page <= totalPages) {
      const res = await fetch(
        `${BACKEND_URL}/api/contents?per_page=100&page=${page}`,
      );
      if (!res.ok) {
        throw new Error(`API returned ${res.status}`);
      }
      const json = (await res.json()) as ApiListResponse;
      allItems.push(...json.data);
      totalPages = json.meta.total_pages;
      page++;
    }

    contentCache = { items: allItems, fetchedAt: Date.now() };
    return allItems;
  } catch (err) {
    console.error('Failed to fetch content for sitemap/feed:', err);
    // 回傳快取（即使過期）或空陣列
    return contentCache?.items ?? [];
  }
}

function escapeXml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// Sitemap XML — 靜態頁面 + 從 API 動態取得的已發布內容
app.get('/sitemap.xml', async (_req, res) => {
  const now = new Date().toISOString().split('T')[0];

  const staticUrls = STATIC_ROUTES.map(
    (route) =>
      `  <url>
    <loc>${SITE_URL}${route.path}</loc>
    <lastmod>${now}</lastmod>
    <changefreq>${route.changefreq}</changefreq>
    <priority>${route.priority}</priority>
  </url>`,
  );

  const contents = await fetchPublishedContent();

  const priorityMap: Record<string, string> = {
    article: '0.7',
    essay: '0.6',
    til: '0.4',
    note: '0.4',
  };

  const contentUrls = contents
    .filter((c) => TYPE_ROUTE_PREFIX[c.type])
    .map((c) => {
      const prefix = TYPE_ROUTE_PREFIX[c.type];
      const lastmod = (c.published_at ?? c.updated_at).split('T')[0];
      const priority = priorityMap[c.type] ?? '0.5';
      return `  <url>
    <loc>${SITE_URL}${prefix}/${c.slug}</loc>
    <lastmod>${lastmod}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>${priority}</priority>
  </url>`;
    });

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${[...staticUrls, ...contentUrls].join('\n')}
</urlset>`;

  res.set('Content-Type', 'application/xml');
  res.set('Cache-Control', 'public, max-age=3600');
  res.send(xml);
});

// RSS Feed — 從 API 動態取得所有已發布內容
app.get('/feed.xml', async (_req, res) => {
  const contents = await fetchPublishedContent();

  const feedItems = contents
    .filter((c) => TYPE_ROUTE_PREFIX[c.type])
    .sort(
      (a, b) =>
        new Date(b.published_at ?? b.updated_at).getTime() -
        new Date(a.published_at ?? a.updated_at).getTime(),
    );

  const latestDate =
    feedItems.length > 0
      ? new Date(
          feedItems[0].published_at ?? feedItems[0].updated_at,
        ).toUTCString()
      : new Date().toUTCString();

  const items = feedItems
    .map((c) => {
      const prefix = TYPE_ROUTE_PREFIX[c.type];
      const link = `${SITE_URL}${prefix}/${c.slug}`;
      const pubDate = new Date(c.published_at ?? c.updated_at).toUTCString();
      const categories = c.tags
        .map((tag) => `      <category>${escapeXml(tag)}</category>`)
        .join('\n');
      return `    <item>
      <title>${escapeXml(c.title)}</title>
      <link>${link}</link>
      <guid isPermaLink="true">${link}</guid>
      <description>${escapeXml(c.excerpt)}</description>
      <pubDate>${pubDate}</pubDate>
${categories}
    </item>`;
    })
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
const BFF_MAX_BODY_BYTES = 10 * 1024 * 1024; // 10 MB

app.use('/bff', (req, res) => {
  const targetUrl = `${BACKEND_URL}${req.originalUrl.replace(/^\/bff/, '')}`;
  const headers: Record<string, string> = {
    'content-type': req.headers['content-type'] || 'application/json',
  };

  // 轉發真實 client IP，讓後端 rate limiter 按用戶限流
  const clientIp =
    (req.headers['cf-connecting-ip'] as string) ||
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.socket.remoteAddress ||
    '';
  if (clientIp) {
    headers['x-forwarded-for'] = clientIp;
  }

  const forwardHeaders = [
    'authorization',
    'cookie',
    'x-hub-signature-256',
    'x-github-event',
    'x-github-delivery',
    'x-notion-signature',
  ];
  for (const h of forwardHeaders) {
    if (req.headers[h]) {
      headers[h] = req.headers[h] as string;
    }
  }

  // 限制 body 大小，防止記憶體 DoS
  let receivedBytes = 0;
  const bodyChunks: Buffer[] = [];

  req.on('data', (chunk: Buffer) => {
    receivedBytes += chunk.length;
    if (receivedBytes > BFF_MAX_BODY_BYTES) {
      req.destroy();
      res.status(413).json({ error: 'Payload too large' });
      return;
    }
    bodyChunks.push(chunk);
  });

  req.on('end', () => {
    if (receivedBytes > BFF_MAX_BODY_BYTES) {
      return;
    }
    const body = bodyChunks.length > 0 ? Buffer.concat(bodyChunks) : undefined;
    fetch(targetUrl, {
      method: req.method,
      headers,
      body,
    })
      .then(async (upstream) => {
        res.status(upstream.status);
        upstream.headers.forEach((value, key) => {
          if (
            !['transfer-encoding', 'content-encoding'].includes(
              key.toLowerCase(),
            )
          ) {
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

// 靜態檔案
app.use(
  express.static(browserDistFolder, {
    maxAge: '1y',
    index: false,
    redirect: false,
  }),
);

// Angular SSR
app.get('/{*path}', (req, res, next) => {
  angularApp
    .handle(req)
    .then((response) => {
      if (response) {
        writeResponseToNodeResponse(response, res);
      } else {
        next();
      }
    })
    .catch((err) => {
      console.error(`SSR error on ${req.method} ${req.originalUrl}:`, err);
      next(err);
    });
});

if (isMainModule(import.meta.url)) {
  const port = process.env['PORT'] || 4000;
  app.listen(port, () => {
    console.log(`Node Express server listening on http://localhost:${port}`);
  });
}

export default createNodeRequestHandler(app);
