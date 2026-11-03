# Nous OSINT frontend

Browser-rendered read-only information portal built with Quasar 2 / Vue 3 / TypeScript and Quasar CLI with Vite. Visual direction: source-first research feed; not a clone of Feedly.

## Local development

Requires Node.js 24 (or 22.22+), npm and a **separately running loopback-only** Nous FastAPI service at `127.0.0.1:8000`.

```bash
cd ui
npm ci
npm run dev
```

Open `http://127.0.0.1:9000`. In development Quasar proxies `/v1` to the loopback API. **Do not publish the dev server or use this proxy as an authentication boundary.**

## Verification

```bash
npm run typecheck
npm run build
```

The static files are emitted to `ui/dist/spa`. Serve these from a static host; **no Node/Quasar server runs on the Nous VM**. The UI uses hash-based routes, so it needs no SPA URL rewrite.

### Production ingress

The static build is baked into the MCP origin image and served at `/` behind the existing Access-required Tunnel. The origin validates the Access JWT for static assets and proxies only GET requests for the UI's allowlisted `/v1` routes to the private API. It does not publish `/api/v1`, diagnostics, administration or PostgreSQL. The Tunnel and Cloudflare Access configuration are managed separately and were not changed for this UI deployment.

## Pages

- Explore: keyword, kind/source filters and cursor-based incremental results (max 40 per request).
- Item detail: current metadata, source hyperlink, provenance and immutable revisions.
- Changes: 7/30/90 day window and server-bounded change reports.
- Sources: enabled state, error, last successful collection and next poll.

**Not implemented by the backend**: user-defined watches, RSS exports and write/manage endpoints. The UI intentionally has no placeholder action for them. No production fixtures, embedded credentials or HTML rendering of retrieved content.

See [UI design contract](../docs/UI_DESIGN.md).
