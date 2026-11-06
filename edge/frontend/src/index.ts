/**
 * Static UI-only Worker. Zone Worker Routes select UI paths; API, MCP, OAuth
 * discovery and reports MUST bypass the Worker and go straight to Tunnel.
 * Never add fetch(request) origin fallback to this module.
 * Authentication is owned by Cloudflare Access and verified at the origin.
 */
export interface Env {
  ASSETS: { fetch(request: Request): Promise<Response> };
}

// Compatibility authority: src/nous/access_auth.py (_SPA_ROUTE, _STATIC_ASSET).
const spaRoute = /^\/(?:explore|changes|sources|sources\/new|admin\/sources|admin\/sources\/new|admin\/reports|admin\/sources\/[a-z][a-z0-9-]{2,99}\/edit|items\/[0-9]+|cves\/CVE-[0-9]{4}-[0-9]{4,})$/;
const assetPath = /^\/assets\/[A-Za-z0-9._-]{1,255}$/;
export type Destination = 'index' | 'asset' | 'not-found';

export function classify(request: Request): Destination {
  const url = new URL(request.url);
  if (url.protocol !== 'https:' || url.hostname !== 'nous.yohn.jp' ||
      (url.port !== '' && url.port !== '443') ||
      !['GET', 'HEAD'].includes(request.method)) return 'not-found';
  const path = url.pathname;
  const rawPath = request.url.match(/^https:\/\/[^/?#]+([^?#]*)/)?.[1] || '/';
  // URL parsing may normalize traversal: do not turn malformed paths into SPA.
  if (rawPath !== path || rawPath.includes('%') ||
      rawPath.includes('\\') || rawPath.includes('//')) return 'not-found';
  if (path === '/' || path === '/index.html' || spaRoute.test(path)) return 'index';
  if (assetPath.test(path)) return 'asset';
  return 'not-found';
}

export async function dispatch(request: Request, env: Env): Promise<Response> {
  const destination = classify(request);
  if (destination === 'not-found') {
    return new Response(request.method === 'HEAD' ? null : 'Not Found\n', {
      status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
    });
  }
  const assetURL = new URL(request.url);
  if (destination === 'index') assetURL.pathname = '/index.html';
  assetURL.search = '';
  const response = await env.ASSETS.fetch(new Request(assetURL, request));
  const headers = new Headers(response.headers);
  headers.delete('CDN-Cache-Control');
  headers.delete('Cloudflare-CDN-Cache-Control');
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Content-Type-Options', 'nosniff');
  return new Response(request.method === 'HEAD' ? null : response.body, {
    status: response.status, statusText: response.statusText, headers,
  });
}

export default {
  fetch(request: Request, env: Env): Promise<Response> { return dispatch(request, env); },
};
