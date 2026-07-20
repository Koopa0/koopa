import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import test from 'node:test';

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert(address && typeof address !== 'string');
  return `http://127.0.0.1:${address.port}`;
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

test('production RSS and sitemap consume the backend public content contract without stale fallback', async (t) => {
  let contents = [
    {
      id: '01900000-0000-7000-8000-000000000001',
      slug: 'withdrawal-contract-probe',
      title: 'A <public> snapshot',
      body: 'Public body',
      excerpt: 'Public excerpt',
      type: 'article',
      status: 'published',
      topics: [
        {
          id: '01900000-0000-7000-8000-000000000002',
          slug: 'engineering',
          name: 'Engineering & Operations',
        },
      ],
      is_public: true,
      reading_time_min: 1,
      published_at: '2026-07-20T01:02:03Z',
      created_at: '2026-07-20T01:00:00Z',
      updated_at: '2026-07-20T01:02:03Z',
    },
  ];

  const backend = createServer((req, res) => {
    if (!req.url?.startsWith('/api/contents?')) {
      res.writeHead(404).end();
      return;
    }
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        data: contents,
        meta: { total: contents.length, page: 1, per_page: 100, total_pages: 1 },
      }),
    );
  });
  const backendURL = await listen(backend);
  process.env['BACKEND_URL'] = backendURL;
  process.env['SITE_URL'] = 'https://example.test';

  const serverModule = new URL(
    '../dist/koopa0dev/server/server.mjs',
    import.meta.url,
  );
  const { reqHandler } = await import(
    `${serverModule.href}?syndication-contract=${Date.now()}`
  );
  const frontend = createServer(reqHandler);
  const frontendURL = await listen(frontend);
  t.after(async () => {
    await Promise.all([close(frontend), close(backend)]);
  });

  for (const path of ['/feed.xml', '/sitemap.xml']) {
    const response = await fetch(frontendURL + path);
    assert.equal(response.status, 200, `${path} must render from the public DTO`);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const body = await response.text();
    assert.match(body, /withdrawal-contract-probe/);
    if (path === '/feed.xml') {
      assert.match(body, /<category>Engineering &amp; Operations<\/category>/);
    }
  }

  // A later request observes the backend's withdrawn projection immediately;
  // the production SSR layer must not resurrect the prior public bytes.
  contents = [];
  for (const path of ['/feed.xml', '/sitemap.xml']) {
    const response = await fetch(frontendURL + path);
    assert.equal(response.status, 200);
    assert.doesNotMatch(await response.text(), /withdrawal-contract-probe/);
  }
});
