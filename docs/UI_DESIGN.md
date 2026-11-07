# Nous OSINT — UI design contract

Updated: 2026-11-07  
State: Quasar SPA / Astro publication implemented. Authenticated browser acceptance and rollback remain **NOT VERIFIED**.  
Authority: [ARCHITECTURE.md](ARCHITECTURE.md), [FRONTEND_EXECUTION_POLICY.md](FRONTEND_EXECUTION_POLICY.md), [EDGE_FRONTEND_DEPLOYMENT.md](EDGE_FRONTEND_DEPLOYMENT.md), [AUTOMATED_INTELLIGENCE_REPORTS.md](AUTOMATED_INTELLIGENCE_REPORTS.md).

## Purpose and visual system

Nous is an intelligence desk for reading observed records, assessing provenance and tracing changes, not a promotional dashboard. The dominant artifact is the collected title or the published report; source identity, timestamp, evidence and state come next. Use a continuous scan-friendly register, an evidence reading lane and an accessible operational layout.

- Quasar 2 + Vue 3 + TypeScript `ui/` and Astro `reports/site/` share paper/panel, deep ink, measured blue action, warm provenance accents and restrained separators. Source text remains plain escaped content.
- Use real API data only. Loading, empty, permission denied, failed, unknown, disabled and stale states must not collapse into the same visual state.
- Color supports meaning but does not replace status labels. Focus is visible, targets are usable on touch, Japanese titles and identifiers wrap without horizontal clipping.
- Motion is short action feedback, not delayed content appearance; honor `prefers-reduced-motion`. No invented counts, decorative charts, fake progress or pseudo-buttons.

## Art direction — research workstation, not a generic dashboard

We compared a promotional news-feed composition with a split register-and-dossier workspace. The selected instrument preserves a scannable primary table and puts the provenance dossier beside it. The main object is the real ingested record, not an invented threat score or a decorative health chart.

The exploration register is a genuine table: record title/kind, organization/source, published-or-observed time, explicit lifecycle state and version. Only the title is an interactive button (not the table row), honoring table semantics and keyboard navigation. In compact mode it favors rapid scanning; standard mode allows multi-line titles. Row numbers indicate sequence on the loaded page, **not priority, severity or global ranking**. The same URL stores `q`, `kind`, `source` and optionally selected `item`. Selected item is inspected inline from 1200px upward, otherwise opened as a document route. The inspector can be closed, resized between 300–640px by pointer or arrow keys, and switched among Overview, Attributes/Provenance and Observation History using existing immutable item/version APIs. Filter chips support independent removal; `/` focuses search, and `j/k` advances selection outside form controls. Arrow keys only change the record while focus is inside the register.

The common navigational geometry is a 54px brand/search bar, a 186px research/publications/operations rail on desktop, and mobile destinations on narrow screens. The Astro publication experience uses the same header and rail for orientation but remains a separate, script-free static renderer. Its archive is a publication register of **actual** report content: category, date, report title, verified claim-classification counts, evidence count and documented KEV status; no CVSS/EPSS scores without a verified source field. Article pages keep their reading lane, linked citations and source list. The report admin displays counts **within the loaded API page**, filterable observed execution states, the last successful refresh, and real run stage/events without fake progress bars or ETAs.

Visual language: neutral paper/graphite, restrained institutional blue for interactions, desaturated warm provenance marker; one thin-rule grammar and contextual typesetting. No marketing hero, card-wall KPIs, stock images, shaders, cyber neon, decorative background gradients or fabricated telemetry. Short CSS transitions only on selection, navigation, filtering and first-record entry, with `prefers-reduced-motion` removing animations. Compact data cells retain title access on mobile and show source/time inline. Light/low-contrast appearances are not a substitute for accessible keyboard focus or statuses in text.

References were interpreted selectively: [Taste Skill](https://github.com/Leonxlnx/taste-skill/blob/main/skills/taste-skill/SKILL.md) for content-specific identity, consistent alignment and restrained finishing; [DADS](https://design.digital.go.jp/dads/) for data tables, typography and accessibility; [Impeccable](https://github.com/pbakaus/impeccable) for critique/distill/harden; [Linear](https://linear.app/now) for navigation receding behind the work object; [OpenCTI](https://docs.opencti.io/latest/usage/filters/) for URL-persisted investigation filters. We did not incorporate external runtime code/assets or the marketing-site-specific rules. User-supplied UX audit identifies useful friction, but speculative real-time protocols, STIX export, severity signals and hardcoded 32px rows are **not approved API contracts**.

## Published article — provenance dossier

The **article reading view** is the primary result of this system. The previous PRs revised the report index and shell but left individual article pages structurally unchanged. The new dossier composition is intentionally unlike a card-based blog: it treats the publication as an auditable research document.

1. **Cover:** compact publication strip, real category/template/date, report title and a concise deck. A provenance stamp exposes actual source and claim counts. The segmented strip represents observed/inferred/unconfirmed **claim counts, not confidence, incident severity or a CVSS estimate**. Legend text stays visible in every mode.
2. **Editorial brief:** all saved summary points are presented as numbered reading anchors with substantive text; no fabricated abstract, score or additional model-generated information.
3. **Reading tracks:** a sectional contents rail, restrained ~40-Japanese-character prose measure with 1.85–1.9 line-height, and a source register with anchored evidence IDs, publisher, observed/published times and relation type. Evidence tags link to the canonical source ID; `:target` highlights the destination without any JavaScript.
4. **CVE:** preserve the three-valued KEV catalog status and freshness caveat. No visual red severity signal for `not_listed` or `unknown`.
5. **Responsive:** at wide widths, display three parallel tracks; at intermediate widths, a visible contents strip above body + source rail; at narrow widths, title, provenance summary, executive brief, contents, full article and source list in that sequence. Print removes chrome but preserves article and source metadata.
6. **Motion:** only modest cover/brief entrance and source-target acknowledgement, with `prefers-reduced-motion` removing it. Never infer processing or scoring from an animation.

Both article schema v1 blocks and v2 claim-only sections remain supported. This document describes the **actual static Astro renderer**, not a client SPA: the release gate rejects scripts and unsafe URLs, so interactions rely on links, native document landmarks and CSS.

### Why a report style change previously failed to appear

A published report is a *content-addressed HTML+asset release* built by the private report Worker. Merging a Quasar Worker UI PR never updates this origin-side static release. The report image now records a deterministic fingerprint of its bundled Astro renderer in the private release manifest. On the next Worker tick after deployment of a changed report image, a revision mismatch triggers the existing serialized, validated rebuild from immutable DB article JSON and atomic promotion, without re-running Codex or creating new report rows. A failed build preserves the current public pointer; old releases and asset hashes remain for rollback.

This propagation mechanism does **not** mean GitHub CI alone has deployed a report Worker image or switched the live site. The runtime verification must record the image digest, active before/after site digest, authenticated `/reports/` and a specific article URL, plus rollback evidence.

## Navigation and interaction contract

| Surface | Primary user action | State and return path |
| --- | --- | --- |
| Explore | Query/filter bounded records; select item; request next cursor page | URL retains `q`, `kind`, `source`, optional selected `item` |
| Item detail | Verify publisher URL, timestamps, attributes, provenance and recent immutable versions | Allowlisted internal `returnTo` preserves Explore, Changes or CVE origin; other targets fall back to Explore |
| Changes | Compare observed revisions over 7/30/90 days | Open underlying record; do not invent chronological diff details |
| Sources | Find and filter registered sources, distinguish enabled config from successful fetch | Admin actions require independent origin authorization |
| CVE / KEV | Differentiate listed, fresh not-listed and unknown; inspect related evidence | Return to the originating Explore/Item view; mentions are not KEV confirmation |
| Source admin/onboarding | Maintain reviewed custom sources or generate Git review definitions | Disabled-by-default registration and explicit confirmation for destructive/enable actions |
| Report admin | Enqueue template runs; inspect actual state/stage/events and schedules | Queued is not published; read published output in `/reports/` |
| Report publication | Read article, follow claim/evidence references, navigate back to the library | Persistent shared navigation and contextual links to archive, evidence and Explore |

Desktop uses a left navigation rail and, from 1200px upward, an optional resizable record preview. Below that breakpoint, selecting a record opens a readable detail route. Mobile uses bottom navigation, inline source/time metadata and full-width actions. Report articles use a reading column and a reference register: sticky alongside on wide screens, placed after the body on narrow screens. The workspace nav remains available across the SPA and separate report pages.

## Technical contracts

- Same-origin `/v1` GET for research; admin mutation endpoints are separately role-protected. Never expose a client token, SQL or untrusted HTML.
- Bounded `/v1/items` cursor pagination; cancel stale requests when filters change. Independent errors do not imply zero sources or records.
- Source state must distinguish **configured enabled**, **successful collection**, and **last error**; do not derive service health from enabled alone.
- Static SPA routes on Cloudflare must remain narrow. `/v1/*`, `/mcp*`, OAuth and `/reports/*` remain behind the existing Access/Tunnel origin. No catch-all Worker forwarding.
- Astro outputs are built one-shot by the report Worker, not rendered by a persistent VM frontend server. Its trusted renderer rejects scripts, JS assets, unapproved internal links and external links without `noopener noreferrer`. Keep archive filtering server-side or omit it rather than weakening this gate.

## Verification gates

1. `ui/` typecheck and production build; `reports/site/` build and report fixtures.
2. 320px, 390px, 1199px, 1200px and 1440px: navigation, overflowing text, filtering, item return, source-status triage, report-to-library return, and long evidence registers.
3. Keyboard (`/`, `j/k`, arrow keys inside register, resize keys), focus return, Japanese IME, contrast, dark mode, reduced motion, loading, empty, permission and error states.
4. Actual API/JWT/role checks and live Cloudflare routing, including unknown paths and rollback, separately from CI.

**A checked code path is not a verified live browser or deployment path.** Record runtime test evidence only when it is actually observed.

## Design references

[Impeccable](https://github.com/pbakaus/impeccable) was used for the audit vocabulary (critique, distill, polish, harden, adapt), not installed as a runtime dependency. No external CSS, assets or automated install hooks are copied into this product.
