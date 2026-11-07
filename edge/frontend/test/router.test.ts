import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { classify, dispatch } from '../src/index.ts';

const request = (path: string, method = 'GET') => new Request(`https://nous.yohn.jp${path}`, { method, redirect: 'manual' });
const env = { ASSETS: { async fetch(req: Request) {
  const path = new URL(req.url).pathname;
  return new Response(req.method === 'HEAD' ? null : path === '/index.html' ? '<html>SPA</html>' : 'asset', {
    status: path.includes('missing') ? 404 : 200,
    headers: { 'Content-Type': path === '/index.html' ? 'text/html' : 'text/javascript', 'Content-Security-Policy': "default-src 'self'" },
  });
} } };

test('only documented UI GET/HEAD renders SPA entry', async () => {
  for (const path of ['/', '/index.html', '/live', '/explore', '/changes', '/sources', '/sources/new', '/items/1', '/cves/CVE-2026-12345', '/admin/sources', '/admin/sources/new', '/admin/sources/example/edit', '/admin/reports', '/explore?q=security']) {
    for (const method of ['GET', 'HEAD']) {
      assert.equal(classify(request(path, method)), 'index');
      const response = await dispatch(request(path, method), env);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(response.headers.get('content-security-policy'), "default-src 'self'");
      assert.equal(await response.text(), method === 'HEAD' ? '' : '<html>SPA</html>');
    }
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
      assert.equal(classify(request(path, method)), 'not-found');
      assert.equal((await dispatch(request(path, method), env)).status, 404);
    }
  }
});

test('never proxy or turn backend, OAuth, malformed, or unknown paths into SPA', async () => {
  for (const path of ['/v1/items?q=security', '/v1/admin/report-runs', '/v1', '/mcp', '/mcp/', '/mcp/tools', '/reports', '/reports/', '/reports/_astro/file.css', '/.well-known/oauth-protected-resource', '/cdn-cgi/access/login', '/api/v1/items', '/health', '/internal', '/metrics', '/admin/unknown', '/assets/nested/file.js', '/assets/%2e%2e%2findex.html', '/expl%6fre', '/%ZZ', '//explore', '/explore//', '/explore.json', '/_private', '/V1/items', '/sources-secret']) {
    assert.equal(classify(request(path)), 'not-found', path);
    const response = await dispatch(request(path), env);
    assert.equal(response.status, 404);
    assert.notEqual(await response.text(), '<html>SPA</html>');
  }
  for (const path of ['/assets/missing.js', '/assets/index.html', '/assets/v1']) {
    assert.equal(classify(request(path)), 'asset');
    const result = await dispatch(request(path), env);
    assert.notEqual(await result.text(), '<html>SPA</html>');
  }
  assert.equal((await dispatch(request('/assets/missing.js'), env)).status, 404);
  assert.equal((await dispatch(request('/admin/unknown', 'HEAD'), env)).status, 404);
});

test('static paths are selected by explicit zone routes; dynamic paths bypass Worker entirely', async () => {
  const terraform = await readFile(new URL('../../../deploy/cloudflare/terraform/main.tf', import.meta.url), 'utf8');
  const paths = [...terraform.matchAll(/^    "(nous\.yohn\.jp[^"]*)",?$/gm)].map(m => m[1]);
  assert.equal(paths.length, 11);
  assert(!paths.includes('nous.yohn.jp/*'), 'catch-all Worker Route forbidden');
  const matches = (path: string) => paths.some(route => {
    const requestURL = 'nous.yohn.jp' + path;
    if (route === 'nous.yohn.jp') return path === '/';
    return route.endsWith('*') ? requestURL.startsWith(route.slice(0, -1)) : requestURL === route;
  });
  for (const path of ['/', '/index.html?x=1', '/assets/app-123.js', '/live', '/explore?q=1', '/changes', '/sources/new', '/admin/sources/foo/edit', '/admin/reports', '/items/123', '/cves/CVE-2026-12345']) {
    assert(matches(path), path);
  }
  for (const path of ['/v1/items', '/v1/stream', '/v1/admin/report-runs', '/mcp', '/mcp/tools', '/reports', '/reports/', '/reports/_astro/a.css', '/.well-known/oauth-authorization-server', '/cdn-cgi/access/login', '/health', '/api/v1/items', '/metrics', '/oauth/authorize']) {
    assert(!matches(path), path);
  }
  // Worker Routes do not match query strings for an exact root path. Existing
  // origin UI is retained until this corner case has a supported solution.
  assert(!matches('/?q=1'));
  assert(matches('/sources-unrecognized'));
  assert.equal(classify(request('/sources-unrecognized')), 'not-found');
});

test('routing regexes stay aligned with Python compatibility authority', async () => {
  const python = await readFile(new URL('../../../src/nous/access_auth.py', import.meta.url), 'utf8');
  const typescript = await readFile(new URL('../src/index.ts', import.meta.url), 'utf8');
  for (const [py, ts] of [['_SPA_ROUTE', 'spaRoute'], ['_STATIC_ASSET', 'assetPath']]) {
    const pattern = python.match(new RegExp(`${py} = re.compile\\(r"([^"\\n]+)"\\)`))![1];
    const jsPattern = typescript.match(new RegExp(`const ${ts} = /(.+)/;`))![1].replaceAll('\\/', '/');
    assert.equal(jsPattern, pattern, `${py} drift`);
  }
});

test('observable traversal is never served as UI despite URL normalization', () => {
  for (const path of ['/assets/%2e%2e/explore', '/assets/../explore', '/%2e/explore', '/assets/..\\explore']) {
    const req = request('/explore');
    Object.defineProperty(req, 'url', { value: `https://nous.yohn.jp${path}` });
    assert.equal(classify(req), 'not-found', path);
  }
  assert.equal(classify(new Request('https://nous-frontend.example.workers.dev/explore')), 'not-found');
});
