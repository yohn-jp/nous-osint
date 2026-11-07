# Nous OSINT — UI design contract

Updated: 2026-11-07  
State: Quasar SPA / Astro publication implemented. Authenticated browser acceptance and rollback remain **NOT VERIFIED**.  
Authority: [ARCHITECTURE.md](ARCHITECTURE.md), [FRONTEND_EXECUTION_POLICY.md](FRONTEND_EXECUTION_POLICY.md), [EDGE_FRONTEND_DEPLOYMENT.md](EDGE_FRONTEND_DEPLOYMENT.md), [AUTOMATED_INTELLIGENCE_REPORTS.md](AUTOMATED_INTELLIGENCE_REPORTS.md).

## Purpose and visual system

Nous is an intelligence desk for reading observed records, assessing provenance and tracing changes, not a promotional dashboard. The dominant artifact is the collected title or the published report; source identity, timestamp, evidence and state come next. Use a continuous scan-friendly register, an evidence reading lane and an accessible operational layout.

- Quasar 2 + Vue 3 + TypeScript `ui/` and Astro `reports/site/` share paper/panel, deep ink, teal action and restrained separators. Source text remains plain escaped content.
- Use real API data only. Loading, empty, permission denied, failed, unknown, disabled and stale states must not collapse into the same visual state.
- Color supports meaning but does not replace status labels. Focus is visible, targets are usable on touch, Japanese titles and identifiers wrap without horizontal clipping.
- Motion is short action feedback, not delayed content appearance; honor `prefers-reduced-motion`. No invented counts, decorative charts, fake progress or pseudo-buttons.

## Navigation and interaction contract

| Surface | Primary user action | State and return path |
| --- | --- | --- |
| Explore | Query/filter bounded records; select item; request next cursor page | URL retains `q`, `kind`, `source`, optional selected `item` |
| Item detail | Verify publisher URL, timestamps, attributes, provenance and recent immutable versions | On narrow layouts, `returnTo` is accepted only for an internal `/explore` URL |
| Changes | Compare observed revisions over 7/30/90 days | Open underlying record; do not invent chronological diff details |
| Sources | Find and filter registered sources, distinguish enabled config from successful fetch | Admin actions require independent origin authorization |
| CVE / KEV | Differentiate listed, fresh not-listed and unknown; inspect related evidence | Mentions of a CVE are not KEV confirmation |
| Source admin/onboarding | Maintain reviewed custom sources or generate Git review definitions | Disabled-by-default registration and explicit confirmation for destructive/enable actions |
| Report admin | Enqueue template runs; inspect actual state/stage/events and schedules | Queued is not published; read published output in `/reports/` |
| Report publication | Read article, follow claim/evidence references, navigate back to the library | Persistent shared navigation and contextual links to archive, evidence and Explore |

Desktop uses a left navigation rail and, only above 1250px, an optional record preview. Below that breakpoint, selecting a record opens a readable detail route. Mobile uses bottom navigation and full-width actions. Report articles use a reading column and a reference register: sticky alongside on wide screens, placed after the body on narrow screens. The workspace nav remains available across the SPA and separate report pages.

## Technical contracts

- Same-origin `/v1` GET for research; admin mutation endpoints are separately role-protected. Never expose a client token, SQL or untrusted HTML.
- Bounded `/v1/items` cursor pagination; cancel stale requests when filters change. Independent errors do not imply zero sources or records.
- Source state must distinguish **configured enabled**, **successful collection**, and **last error**; do not derive service health from enabled alone.
- Static SPA routes on Cloudflare must remain narrow. `/v1/*`, `/mcp*`, OAuth and `/reports/*` remain behind the existing Access/Tunnel origin. No catch-all Worker forwarding.
- Astro outputs are built one-shot by the report Worker, not rendered by a persistent VM frontend server. Publisher links use `noopener noreferrer`.

## Verification gates

1. `ui/` typecheck and production build; `reports/site/` build and report fixtures.
2. 320px, 390px and 1280px: navigation, overflowing text, filtering, item return, source-status triage, report-to-library return, and long evidence registers.
3. Keyboard and screen reader labels, visible focus, Japanese IME, dark mode, reduced motion, loading, empty, permission and error states.
4. Actual API/JWT/role checks and live Cloudflare routing, including unknown paths and rollback, separately from CI.

**A checked code path is not a verified live browser or deployment path.** Record runtime test evidence only when it is actually observed.

## Design references

[Impeccable](https://github.com/pbakaus/impeccable) was used for the audit vocabulary (critique, distill, polish, harden, adapt), not installed as a runtime dependency. No external CSS, assets or automated install hooks are copied into this product.
