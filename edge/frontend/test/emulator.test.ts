import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Miniflare } from 'miniflare';

const root = new URL('../.cloudflare/output/v0/workers/default/', import.meta.url);

test('built static-only Worker serves real Quasar assets and never forwards to origin', async () => {
  const config = JSON.parse(await readFile(new URL('worker.config.json', root), 'utf8'));
  assert.equal(config.workersDev, false);
  assert.equal(config.previewUrls, false);
  assert.equal(config.triggers, undefined);
  assert.equal(config.domains, undefined);
  assert.equal(config.assets.runWorkerFirst, false);
  assert.equal(config.assets.notFoundHandling, 'single-page-application');
  assert.equal(config.env.PASSTHROUGH_ONLY, undefined);
  config.manifest = { mainModule: 'index.js', modules: {
    'index.js': { type: 'esm', contents: await readFile(new URL('bundle/index.js', root), 'utf8') },
  } };
  const calls: string[] = [];
  const mf = new Miniflare({
    cf: false, telemetry: { enabled: false },
    workers: [{ config: { ...config, assets: { ...config.assets, directory: fileURLToPath(new URL('assets/', root)), hasUserWorker: true } },
      dev: { rootPath: fileURLToPath(new URL('bundle/', root)), outboundService: { type: 'fetcher', handler: async req => {
        calls.push(req.url);
        throw new Error('Static-only Worker must not fetch origin');
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
    const assetName = files.find(name => name.endsWith('.js'));
    assert(assetName, 'No Quasar JS asset in build');
    const asset = await mf.dispatchFetch(`https://nous.yohn.jp/assets/${assetName}`);
    assert.equal(asset.status, 200);
    assert.match(asset.headers.get('content-type')!, /javascript/);
    for (const path of ['/unrecognized', '/assets/missing.js', '/assets/index.html',
      '/v1/items', '/v1/admin/report-runs', '/reports', '/reports/', '/.well-known/oauth-protected-resource', '/health']) {
      const response = await mf.dispatchFetch(`https://nous.yohn.jp${path}`);
      assert.equal(response.status, 404, path);
    }
    const mcp = await mf.dispatchFetch('https://nous.yohn.jp/mcp', { method: 'POST', body: 'initialize', headers: { Authorization: 'Bearer opaque', Cookie: 'session=opaque', 'Cf-Access-Jwt-Assertion': 'opaque-jwt' } });
    assert.equal(mcp.status, 404);
    assert.equal(calls.length, 0, 'Worker performed an origin fetch');
  } finally { await mf.dispose(); }
});

// The zone's path-limited Route is tested separately. Directly dispatching to a
// Worker with an unrelated path does not simulate a real Cloudflare Route bypass.
