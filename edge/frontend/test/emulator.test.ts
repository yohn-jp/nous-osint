import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Miniflare, Response } from 'miniflare';

const root = new URL('../.cloudflare/output/v0/workers/default/', import.meta.url);

test('built Worker and real Quasar assets preserve the edge-to-origin contract', async () => {
  const config = JSON.parse(await readFile(new URL('worker.config.json', root), 'utf8'));
  assert.equal(config.workersDev, false);
  assert.equal(config.previewUrls, false);
  assert.equal(config.triggers, undefined);
  assert.equal(config.domains, undefined);
  assert.equal(config.assets.runWorkerFirst, true);
  assert.equal(config.assets.notFoundHandling, 'none');
  config.manifest = { mainModule: 'index.js', modules: {
    'index.js': { type: 'esm', contents: await readFile(new URL('bundle/index.js', root), 'utf8') },
  } };
  const calls: string[] = [];
  const mf = new Miniflare({
    cf: false, telemetry: { enabled: false },
    workers: [{ config: { ...config, assets: { ...config.assets, directory: fileURLToPath(new URL('assets/', root)), hasUserWorker: true } },
      dev: { rootPath: fileURLToPath(new URL('bundle/', root)), outboundService: { type: 'fetcher', handler: async req => {
        calls.push(req.url);
        assert.equal(new URL(req.url).hostname, 'nous.yohn.jp');
        const path = new URL(req.url).pathname;
        if (path === '/mcp') {
          assert.equal(req.headers.get('authorization'), 'Bearer opaque');
          assert.equal(req.headers.get('cookie'), 'session=opaque');
          assert.equal(req.headers.get('cf-access-jwt-assertion'), 'opaque-jwt');
          assert.equal(req.method, 'POST');
          assert.equal(await req.text(), 'initialize');
          return new Response('event: message\ndata: {}\n\n', { headers: { 'Content-Type': 'text/event-stream', 'Mcp-Session-Id': 'session-id', 'Cache-Control': 'no-store' } });
        }
        if (path === '/reports') return new Response(null, { status: 308, headers: { Location: '/reports/' } });
        return new Response('origin-denied', { status: 403, headers: { 'WWW-Authenticate': 'Bearer', 'Cache-Control': 'no-store' } });
      } } },
    }],
  });
  try {
    const ui = await mf.dispatchFetch('https://nous.yohn.jp/explore');
    assert.equal(ui.status, 200);
    assert.match(await ui.text(), /<html/);
    const head = await mf.dispatchFetch('https://nous.yohn.jp/explore', { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(await head.text(), '');
    const files = await readdir(new URL('assets/assets/', root));
    const asset = await mf.dispatchFetch(`https://nous.yohn.jp/assets/${files.find(name => name.endsWith('.js'))}`);
    assert.equal(asset.status, 200);
    assert.match(asset.headers.get('content-type')!, /javascript/);
    for (const path of ['/unrecognized', '/assets/missing.js', '/assets/index.html']) {
      assert.equal((await mf.dispatchFetch(`https://nous.yohn.jp${path}`)).status, 404);
    }
    assert.equal(calls.length, 0);
    for (const [path, method] of [['/v1/items?q=test', 'GET'], ['/v1/admin/report-runs', 'POST'], ['/reports/', 'HEAD'], ['/.well-known/oauth-protected-resource', 'GET'], ['/explore', 'POST']]) {
      const response = await mf.dispatchFetch(`https://nous.yohn.jp${path}`, { method });
      assert.equal(response.status, 403);
      assert.equal(response.headers.get('www-authenticate'), 'Bearer');
    }
    const redirect = await mf.dispatchFetch('https://nous.yohn.jp/reports', { redirect: 'manual' });
    assert.equal(redirect.status, 308);
    assert.equal(redirect.headers.get('location'), '/reports/');
    const mcp = await mf.dispatchFetch('https://nous.yohn.jp/mcp', { method: 'POST', body: 'initialize', headers: { Authorization: 'Bearer opaque', Cookie: 'session=opaque', 'Cf-Access-Jwt-Assertion': 'opaque-jwt' } });
    assert.equal(mcp.headers.get('mcp-session-id'), 'session-id');
    assert.match(await mcp.text(), /event: message/);
  } finally { await mf.dispose(); }
});

test('built passthrough release keeps UI and assets at the synthetic origin', async () => {
  const config = JSON.parse(await readFile(new URL('worker.config.json', root), 'utf8'));
  config.env.PASSTHROUGH_ONLY.value = 'true';
  config.manifest = { mainModule: 'index.js', modules: {
    'index.js': { type: 'esm', contents: await readFile(new URL('bundle/index.js', root), 'utf8') },
  } };
  const mf = new Miniflare({ cf: false, telemetry: { enabled: false }, workers: [{
    config: { ...config, assets: { ...config.assets, directory: fileURLToPath(new URL('assets/', root)), hasUserWorker: true } },
    dev: { outboundService: { type: 'fetcher', handler: async () => new Response('origin-ui', { status: 200, headers: { 'Cache-Control': 'no-store' } }) } },
  }] });
  try {
    for (const path of ['/explore', '/assets/missing.js', '/unrecognized']) {
      const response = await mf.dispatchFetch(`https://nous.yohn.jp${path}`);
      assert.equal(response.status, 200);
      assert.equal(await response.text(), 'origin-ui');
    }
  } finally { await mf.dispose(); }
});
