import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { classify, dispatch } from '../src/index.ts';

const request = (path: string, method = 'GET') => new Request(`https://nous.yohn.jp${path}`, { method, redirect: 'manual' });
const env = { PASSTHROUGH_ONLY: 'false', ASSETS: { async fetch(req: Request) {
  return new Response(req.method === 'HEAD' ? null : new URL(req.url).pathname === '/index.html' ? '<html>SPA</html>' : 'asset', {
    status: new URL(req.url).pathname.includes('missing') ? 404 : 200,
    headers: { 'Content-Type': new URL(req.url).pathname === '/index.html' ? 'text/html' : 'text/javascript', 'Content-Security-Policy': "default-src 'self'" },
  });
} } };
const noOrigin = async () => { throw new Error('Unexpected origin fetch'); };

test('current clean SPA routes support GET/HEAD only', async () => {
  for (const path of ['/', '/index.html', '/explore', '/changes', '/sources', '/sources/new', '/items/1', '/cves/CVE-2026-12345', '/admin/sources', '/admin/sources/new', '/admin/sources/example/edit', '/admin/reports']) {
    for (const method of ['GET', 'HEAD']) {
      assert.equal(classify(request(path, method)), 'index');
      const response = await dispatch(request(path, method), env, noOrigin);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(response.headers.get('content-security-policy'), "default-src 'self'");
      assert.equal(await response.text(), method === 'HEAD' ? '' : '<html>SPA</html>');
    }
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) assert.equal(classify(request(path, method)), 'origin');
  }
});

test('dynamic, reserved, malformed and encoded paths never receive SPA', async () => {
  for (const path of ['/v1/items?q=security&limit=1', '/v1/admin/report-runs', '/v1', '/mcp', '/mcp/', '/mcp/tools', '/mcpfoo', '/reports', '/reports/', '/reports/security/example/', '/reports/_astro/file.css', '/.well-known/oauth-protected-resource', '/cdn-cgi/access/login', '/cdn-cgi', '/api/v1/items', '/health', '/internal', '/metrics', '/admin/unknown', '/assets/nested/file.js', '/assets/%2e%2e%2findex.html', '/expl%6fre', '/%ZZ', '//explore', '/explore//', '/explore.json', '/_private', '/V1/items']) {
    assert.equal(classify(request(path)), 'origin', path);
    const req = request(path);
    const response = new Response('origin 404', { status: 404 });
    assert.equal(await dispatch(req, env, async passed => { assert.equal(passed, req); return response; }), response);
  }
  for (const path of ['/assets/missing.js', '/assets/index.html', '/assets/v1']) {
    assert.equal(classify(request(path)), 'asset');
    const result = await dispatch(request(path), env, noOrigin);
    assert.notEqual(await result.text(), '<html>SPA</html>');
  }
  assert.equal((await dispatch(request('/assets/missing.js'), env, noOrigin)).status, 404);
});

test('safe unknown screens remain 404, including HEAD', async () => {
  for (const method of ['GET', 'HEAD']) {
    const response = await dispatch(request('/unrecognized', method), env, noOrigin);
    assert.equal(response.status, 404);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(await response.text(), method === 'HEAD' ? '' : 'Not Found\n');
  }
});

test('origin request/response identity preserves POST, JWT, OAuth, cookies, redirects and SSE without buffering', async () => {
  for (const path of ['/mcp', '/v1/admin/report-runs', '/reports', '/reports/']) {
    const req = new Request(`https://nous.yohn.jp${path}?opaque=1`, {
      method: path.startsWith('/reports') ? 'HEAD' : 'POST', redirect: 'manual',
      headers: { Authorization: 'Bearer opaque', Cookie: 'CF_Authorization=opaque', 'Cf-Access-Jwt-Assertion': 'untrusted', Accept: 'text/event-stream' },
      ...(path.startsWith('/reports') ? {} : { body: 'request-body' }),
    });
    let controller: ReadableStreamDefaultController<Uint8Array>;
    const stream = new ReadableStream<Uint8Array>({ start(c) { controller = c; c.enqueue(new TextEncoder().encode('event: first\n\n')); } });
    const upstream = new Response(stream, { status: 401, headers: { 'WWW-Authenticate': 'Bearer resource_metadata="/.well-known/oauth-protected-resource"', 'Mcp-Session-Id': 'opaque-session', 'Content-Type': 'text/event-stream', 'Set-Cookie': 'session=opaque', 'Location': '/oauth', 'Cache-Control': 'no-store' } });
    const result = await dispatch(req, env, async passed => {
      assert.equal(passed, req);
      assert.equal(passed.redirect, 'manual');
      if (passed.method === 'POST') assert.equal(await passed.text(), 'request-body');
      return upstream;
    });
    assert.equal(result, upstream);
    assert.equal(result.body, stream);
    const reader = result.body!.getReader();
    assert.match(new TextDecoder().decode((await reader.read()).value), /first/);
    controller!.enqueue(new TextEncoder().encode('event: second\n\n'));
    assert.match(new TextDecoder().decode((await reader.read()).value), /second/);
    controller!.close();
  }
});

test('passthrough forwards every request including UI/assets without identity decisions', async () => {
  for (const path of ['/explore', '/assets/app.js', '/unrecognized', '/mcp']) {
    const req = request(path);
    const denied = new Response('Forbidden', { status: 403 });
    assert.equal(await dispatch(req, { ...env, PASSTHROUGH_ONLY: 'true' }, async passed => { assert.equal(passed, req); return denied; }), denied);
  }
  for (const value of ['', 'forged', 'signed-looking.jwt.value']) {
    const req = new Request('https://nous.yohn.jp/v1/admin/session', { headers: { 'Cf-Access-Jwt-Assertion': value, 'Cf-Access-Authenticated-User-Email': 'admin@example.invalid' } });
    assert.equal((await dispatch(req, env, async () => new Response(null, { status: 403 }))).status, 403);
  }
  assert.equal(classify(new Request('https://nous-frontend.example.workers.dev/explore')), 'origin');
});

test('routing regexes stay aligned with the Python compatibility authority', async () => {
  const python = await readFile(new URL('../../../src/nous/access_auth.py', import.meta.url), 'utf8');
  const typescript = await readFile(new URL('../src/index.ts', import.meta.url), 'utf8');
  for (const [py, ts] of [['_SPA_ROUTE', 'spaRoute'], ['_STATIC_ASSET', 'assetPath'], ['_UNKNOWN_UI_PATH', 'unknownPath']]) {
    const pattern = python.match(new RegExp(`${py} = re.compile\\(r"([^"\\n]+)"\\)`))![1];
    const jsPattern = typescript.match(new RegExp(`const ${ts} = /(.+)/;`))![1].replaceAll('\\/', '/');
    assert.equal(jsPattern, pattern, `${py} drift`);
  }
});

// Some runtimes retain raw path spelling in request.url; never let URL parsing
// silently normalize it into a permitted SPA route.
test('observable traversal remains origin-bound before URL normalization', () => {
  for (const path of ['/assets/%2e%2e/explore', '/assets/../explore', '/%2e/explore', '/assets/..\\explore']) {
    const req = request('/explore');
    Object.defineProperty(req, 'url', { value: `https://nous.yohn.jp${path}` });
    assert.equal(classify(req), 'origin', path);
  }
});
