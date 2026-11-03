# Nous OSINT cache strategy

Status: Cloudflare hostname-scoped cache bypass applied on 2026-11-03; new origin response headers are pending image rollout.
Owner: Nous ingress and collection pipeline. Cache controls must not weaken Access authorization.

## Decision

Cache **only** versioned, identity-independent Quasar static assets at the Cloudflare edge. Do not cache MCP, JSON search responses, status, provenance, HTML entrypoint, authentication failures, or redirects in shared caches.

| Route / layer | Edge policy | Origin / browser policy | Rationale |
| --- | --- | --- | --- |
| `/assets/<hashed>.js`, `.css`, `.svg`, fonts etc. | Eligible under existing static-file cache policy | 2xx `Cache-Control: public, max-age=31536000, immutable` | Content-addressed, no identity, safe to reuse and no per-request VM bandwidth |
| `/`, `/index.html` | **Bypass** | `no-store` | Entrypoint must immediately reference the current asset digest |
| `/v1/*` GET | **Bypass** | `no-store` | Authenticated, mutable data and status; URL alone does not partition identities |
| `/mcp` GET/POST/DELETE | **Bypass** | `no-store` | OAuth bearer/session metadata and stateful tool output must never be cached |
| `/cdn-cgi/*`, unknown paths, 401/403/404/5xx | **Bypass** | `no-store` for responses from our origin | Do not cache auth handshakes, error pages or negative responses |
| Unknown or non-hashed `/assets/*` | Eligible at edge, but origin `no-store` | `no-store` | Prevent caching unversioned or missing assets |

**Security boundary:** Every asset request must still pass Cloudflare Access before a potential CDN cache hit; Nous origin verifies the Access assertion on cache misses. Static bundles must contain no secrets, user-specific data, or sensitive metadata. Cloudflare's CDN is an optimization, never the authorization boundary.

## Observed Cloudflare state and applied change

The `yohn.jp` zone had a global `Cache Everything` rule (`cache: true`, expression `true`) after a Proprium-specific metadata rule. On 2026-11-03 an **additional final cache rule scoped only to Nous** was added without modifying those existing rules:

- Zone: `yohn.jp`.
- Description: `Nous OSINT: bypass CDN for MCP, APIs, HTML and Access flows`.
- Expression: `(http.host eq "nous.yohn.jp" and not starts_with(http.request.uri.path, "/assets/"))`.
- Action: `set_cache_settings` / `cache: false`.
- Rule ID: `b01e50162377489089dfbb279309262a`; initial resulting ruleset version: `10`.
- The previously deployed `Cache Everything` rule remains in place and still applies to `/assets/*`. Cache Rules are evaluated in order; for conflicting `cache` settings, the **last matching rule** wins. Therefore dynamic Nous URLs bypass the broad earlier rule without impacting other hostnames.

Avoid appending a later broad `Cache Everything` rule that overrides this exception. Do **not** change another hostname's cache behavior while managing Nous. If these rules move to Terraform, import/reconcile the shared zone ruleset without replacing unrelated rules.

## Collector HTTP caching and storage

Upstream publisher traffic is a separate concern from the Cloudflare CDN. Existing `fetch()` sends conditional `If-None-Match` and `If-Modified-Since` values when saved, uses source-specific polling budgets, and the worker handles `304` without creating a new version. Retain this deterministic path; never route publisher requests through an undisclosed shared HTTP cache that might violate feed licensing, robots guidance or revision detection. Source rate limits and backoff, not edge caching, determine collection cost.

PostgreSQL remains the sole authoritative data store, with stable content hashes and immutable versions. **Do not add Redis, an application in-memory query cache, or an edge cache for per-user API results** without measured demand and a defined cache key, invalidation and authorization model. Such a cache would add stale-data and identity-isolation failure modes without proven benefit on a single VM.

## Verification and rollback

After deploying the GitHub Actions-built application digest:

1. Request `/` and `/v1/sources` as an authorized user. Both must return `Cache-Control: no-store` and must **not** report `CF-Cache-Status: HIT`; repeat the requests to verify.
2. Request a real versioned `/assets/*.js` URL twice with valid Access authentication. Expect the immutable origin directive, and verify actual `CF-Cache-Status` (`MISS` followed by `HIT` where edge storage applies); do not assume HIT without observation.
3. Without Access authorization, the same static asset must be denied **even when cached**. Verify Access audit log and origin behavior. This is a required security gate.
4. Send `POST /mcp` and verify no cache hit, functional `initialize`/`tools/list`, and no extra auth error from cache.
5. Confirm the new zone rule is **after** the global `Cache Everything` rule and that the Proprium rule IDs and configuration are unchanged.
6. Monitor Cloudflare cache analytics for `nous.yohn.jp`, origin requests, response bytes, and change/read latency before considering more complexity.

Rollback is to delete **only** the Nous bypass rule by its immutable rule ID (and revert origin header changes through the previous application image if necessary). Do not delete or overwrite the zone-wide ruleset. Rollback of the bypass is **not recommended** while `Cache Everything` exists; prefer temporarily bypassing all Nous paths if asset caching creates trouble.

## Reference

- Cloudflare [default cache behavior](https://developers.cloudflare.com/cache/concepts/default-cache-behavior/)
- Cloudflare [Cache Rules ordering](https://developers.cloudflare.com/cache/how-to/cache-rules/order/)
- Cloudflare [Origin Cache Control](https://developers.cloudflare.com/cache/concepts/cache-control/)
- Cloudflare [Cache Rules settings](https://developers.cloudflare.com/cache/how-to/cache-rules/settings/)
