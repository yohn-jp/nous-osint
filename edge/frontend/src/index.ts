/** Access is enforced on the canonical hostname BEFORE this Worker runs.
 * Identity headers are never interpreted here; the origin still verifies JWTs.
 */
export interface Env {
  ASSETS: { fetch(request: Request): Promise<Response> };
  PASSTHROUGH_ONLY: string;
}

// Compatibility authority: src/nous/access_auth.py (_SPA_ROUTE and unknown UI).
const spaRoute = /^\/(?:explore|changes|sources|sources\/new|admin\/sources|admin\/sources\/new|admin\/reports|admin\/sources\/[a-z][a-z0-9-]{2,99}\/edit|items\/[0-9]+|cves\/CVE-[0-9]{4}-[0-9]{4,})$/;
const assetPath = /^\/assets\/[A-Za-z0-9._-]{1,255}$/;
const unknownPath = /^\/(?:[A-Za-z0-9_-]{1,128}\/)*[A-Za-z0-9_-]{1,128}\/?$/;
const reserved = new Set(['api', 'v1', 'mcp', 'admin', 'internal', 'health', 'metrics', 'reports', 'assets']);
export type Destination = 'origin' | 'index' | 'asset' | 'not-found';

export function classify(request: Request): Destination {
  const url = new URL(request.url);
  if (url.protocol !== 'https:' || url.hostname !== 'nous.yohn.jp' ||
      (url.port !== '' && url.port !== '443') ||
      !['GET', 'HEAD'].includes(request.method)) return 'origin';
  const path = url.pathname;
  const rawPath = request.url.match(/^https:\/\/[^/?#]+([^?#]*)/)?.[1] || '/';
  // Do not decode, normalize, or broaden the origin's ASCII/exact-path rules.
  if (rawPath !== path || rawPath.includes('%') || rawPath.includes('\\') || rawPath.includes('//')) return 'origin';
  if (path.startsWith('/mcp')) return 'origin';
  if (path === '/' || path === '/index.html' || spaRoute.test(path)) return 'index';
  if (assetPath.test(path)) return 'asset';
  const first = path.split('/')[1]!.toLowerCase();
  if (unknownPath.test(path) && !reserved.has(first) && !first.startsWith('_') &&
      !['cdn-cgi'].includes(first)) return 'not-found';
  return 'origin';
}

export async function dispatch(request: Request, env: Env,
  origin: (request: Request) => Promise<Response> = fetch): Promise<Response> {
  const destination = env.PASSTHROUGH_ONLY === 'true' ? 'origin' : classify(request);
  // Preserve the Request and Response, including streams, redirects and challenges.
  // Incoming Worker requests have redirect mode manual. Never reconstruct or buffer.
  if (destination === 'origin') return origin(request);
  if (destination === 'not-found') return new Response(request.method === 'HEAD' ? null : 'Not Found\n', {
    status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
  });
  const assetURL = new URL(request.url);
  if (destination === 'index') assetURL.pathname = '/index.html';
  assetURL.search = '';
  const response = await env.ASSETS.fetch(new Request(assetURL, request));
  const headers = new Headers(response.headers);
  headers.delete('CDN-Cache-Control');
  headers.delete('Cloudflare-CDN-Cache-Control');
  // Keep no-store until authenticated immutable asset caching is proven in C.
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Content-Type-Options', 'nosniff');
  return new Response(request.method === 'HEAD' ? null : response.body, {
    status: response.status, statusText: response.statusText, headers,
  });
}

export default {
  fetch(request: Request, env: Env): Promise<Response> { return dispatch(request, env); },
};
