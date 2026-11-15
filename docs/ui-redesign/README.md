# Nous OSINT — redesign evidence

This record documents the full product redesign on `feat/ui-redesign-v2`, based on `origin/main` at `2f20bc82054feb6828eff7e19d0c8c5c5d9c5929`. It does not use PR #49 as a base. The goal is a daily intelligence instrument connecting awareness, investigation, and publication while keeping the existing API, authorization, provenance, static-rendering, and deployment boundaries intact.

## Design directions and selection

| Direction | Identity and composition | Strength | Trade-off | Decision |
| --- | --- | --- | --- | --- |
| **A — Observation Register** | Warm paper, deep green navigation, copper markers and blue evidence links. Live Feed is chronological; Explore is a full-width index; record inspection gets its own dossier route; reports use a publication archive and a compact editorial opening. | Keeps the observed record or article as the primary object and makes the path from title to evidence direct. The same language spans SPA and static publication without joining their runtimes. | Source health is less prominent than in a monitoring console; operators enter the source directory for operational detail. | **Selected** for the product-wide design. |
| **B — Signal Room** | Dark, dense two-column timeline with a persistent source-health rail and compact operational summaries. | Source health is immediately visible beside incoming events. | Repeats source state alongside records and competes with chronology and report reading. | Built as a separate high-fidelity prototype, evaluated, and rejected. |

The prototype is preserved at [direction-b-signal-room.html](direction-b-signal-room.html), with its [rendered screenshot](screenshots/direction-b-signal-room.png). The comparison focused on identity, composition, scanning efficiency, source identity, evidence access and article reading rather than color preference alone.

## Before and after

Screenshots use a 1440 × 1000 desktop viewport, except the mobile captures at 390 × 844. The before article is rendered from the unmodified `origin/main` build with the same synthetic article fixture. The after article uses the redesigned Astro renderer with that fixture. These are browser captures, not generated mockups.

### Live Feed

Before: flat feed rows, repeated application chrome and weak temporal grouping.

![Live Feed before](screenshots/before/live-desktop.png)

After: actual Tokyo-local observation times form a date rail; each row carries source identity, method, category, publication time, record state and direct source/dossier actions. Refreshing holds the reader's current position and announces newly available records separately.

![Live Feed after](screenshots/after/live-desktop.png)

Mobile preserves the timeline and places filters in a compact native-width layout:

![Live Feed after at mobile width](screenshots/after/live-mobile.png)

### Explore and record dossier

Before: table and selected-record inspector compete for width; titles and provenance are squeezed into adjacent columns.

![Explore before](screenshots/before/explore-desktop.png)

After: a full-width search and record index favors the title, publisher, observed/publication time and explicit record state. Selecting a result opens a dedicated dossier route with overview, source, version and immutable observation history. `returnTo` carries validated internal research context back to the previous result set.

![Explore after](screenshots/after/explore-desktop.png)

![Record dossier after](screenshots/after/item-desktop.png)

Dark mode retains the same geometry and status language:

![Explore in dark mode](screenshots/after/explore-dark-desktop.png)

### Report archive and article

Before: the article spends most of its opening screen inside an oversized cover. The summary begins around y=722; substantive analysis is below the viewport. The contents rail collapses into narrow, vertical Japanese labels.

![Published article before](screenshots/before/article-desktop.png)

After: the title opens at y≈184; the “read first” conclusions begin around y≈392, and the first section with claim-linked evidence begins around y≈560. The fixture's 18 claims and 18 sources are visible in the article document. The contents rail stays readable and the source register remains traceable.

![Published article after](screenshots/after/article-desktop.png)

![Published article at mobile width](screenshots/after/article-mobile.png)

The evidence register keeps evidence IDs, source identity/relation, captured and published dates, license, and publisher navigation in a compact register:

![Article evidence register](screenshots/after/article-source-register-desktop.png)

The archive is now a publication register showing dates, categories, report summaries, evidence counts and classification totals. This fixture intentionally has one article; the open space reflects the actual archive content and is not filled with invented reports.

![Report archive before](screenshots/before/archive-desktop.png)

![Report archive after](screenshots/after/archive-desktop.png)

![Report archive at mobile width](screenshots/after/archive-mobile.png)

### Operations and other research surfaces

The shared visual language also covers source discovery, source configuration, collection history, CVE/KEV state and report execution. The run view separates ad-hoc configuration, execution/history and schedules; an actual failed run is selected so error-stage, retry-count and event state are visible. Source configuration, last successful fetch, last error and unknown state remain separate facts.

![Source directory](screenshots/after/sources-desktop.png)

![Observation history](screenshots/after/changes-desktop.png)

![CVE/KEV unknown state](screenshots/after/cve-unknown-desktop.png)

![Source administration](screenshots/after/admin-sources-desktop.png)

![Report administration with failed-run detail](screenshots/after/admin-reports-desktop.png)

## Synthetic article fixture

The rich test-only report in `reports/site/test-fixtures/article-v2.json` has 3 sections, 18 claims, 18 sources and 18 evidence references: 8 observed facts, 6 inferences and 4 unconfirmed claims. It exercises internal and external source relations, captured/published timestamps, mixed nullable source metadata, the contents rail, claim anchors, citation anchors, source register and print layout. Build validation confirms all claim IDs resolve to their sources, the report emits zero scripts, and the archive uses the actual fixture counts. It is not part of `src/content/reports` and is not published as a live report.

## Modern Web Guidance

The official [GoogleChrome Modern Web Guidance](https://github.com/GoogleChrome/modern-web-guidance) was searched and retrieved with `npx -y modern-web-guidance@latest`; the retrieved package version was `2026_11_09-5bcc021b`. The guidance informed implementation after the design direction was chosen.

| Retrieved guidance | Implementation decision |
| --- | --- |
| [Responsive design](https://github.com/GoogleChrome/modern-web-guidance/blob/main/skills/modern-web-guidance/guides/css/responsive-design.md), [CSS layout](https://github.com/GoogleChrome/modern-web-guidance/blob/main/skills/modern-web-guidance/guides/css/css-layout.md) and [responsive tables](https://github.com/GoogleChrome/modern-web-guidance/blob/main/skills/modern-web-guidance/guides/ui-atoms/responsive-table.md) | Recompose Live Feed and Explore as information registers instead of shrinking the old table/inspector. Use responsive Grid/Flexbox, logical sizing and `@container` when the component width determines its layout. |
| [Typography](https://github.com/GoogleChrome/modern-web-guidance/blob/main/skills/modern-web-guidance/guides/visual-design/typography.md) | Use Japanese-aware line measure and type hierarchy for claims and report reading; keep identifiers and evidence labels legible without clipping. |
| [Content-first noise reduction](https://github.com/GoogleChrome/modern-web-guidance/blob/main/skills/modern-web-guidance/guides/user-experience/content-first-noise-reduction.md) | Remove redundant KPI/dashboard framing and oversized article cover; prioritize real titles, conclusions, source identities and claim-linked evidence. |
| [Accessibility](https://github.com/GoogleChrome/modern-web-guidance/blob/main/skills/modern-web-guidance/guides/accessibility/accessibility.md) | Preserve native links/buttons, visible focus, text status labels, reduced-motion handling and browser-native anchor navigation. Keep all below-fold evidence links keyboard reachable. |
| [Defer rendering heavy content](https://github.com/GoogleChrome/modern-web-guidance/blob/main/skills/modern-web-guidance/guides/performance/defer-rendering-heavy-content.md) and [improve next-page load performance](https://github.com/GoogleChrome/modern-web-guidance/blob/main/skills/modern-web-guidance/guides/performance/improve-next-page-load-performance.md) | Defer only the long below-fold article evidence register using `content-visibility: auto` behind `@supports`, with intrinsic size reservation. Keep simple Live/Explore records in normal render flow. Removing the inline inspector from Explore also avoids loading its dossier tab/detail chunks until a record is opened. |

Implementation uses CSS `clamp()`, `@container`, `:focus-visible`, reduced-motion media queries, `100dvh` for the publication rail, and a feature-gated `content-visibility` enhancement. Unsupported capabilities retain ordinary document flow, links and controls.

## Browser verification

The rendered SPA was served against a deterministic local fixture API; the article was served from the actual static Astro build. Browser screenshots and the walkthrough were performed in Chromium. The local harness does not stand in for authenticated Cloudflare Access or the production origin.

- Tested the app and report surfaces at 320, 390, 768, 1024, 1199, 1200 and 1440 px. `document.documentElement.scrollWidth <= innerWidth` held for Live Feed, Explore, dossier, report article and archive at every tested width.
- Explore returned 12 fixture records. Keyboard `j` moved between records; `/` focused the actual Quasar search input. Typing `CVE-2026-48172` and pressing Enter updated the URL and reduced results to one. Selecting it opened the dossier with the query in `returnTo`; the return link and browser reload both restored the query and one-result set.
- Header search navigated from Live Feed to Explore and focused its actual search field. The search selector explicitly handles Quasar's generated input rather than relying on a wrapper ID.
- Publisher links and report source links opened externally with `target="_blank"` and `rel="noopener noreferrer"`. The item dossier displayed its current version and immutable history hash. The report contents link navigated to its section, and claim citations navigated to their matching source IDs.
- All 18 report source links were reachable in normal Tab order, including the final source row. The publication contained zero scripts. Print emulation hid the workspace header and contents navigation while leaving article text and sources in the print document.
- The API error fixture returned 503 and displayed an alert plus retry action. A 403 admin fixture displayed an error and did not expose admin destinations. A synthetic 403 confirms UI behavior only; it does not replace the unchanged backend/Cloudflare role enforcement.
- The KEV fixture exercised `listed`, `not_listed` and `unknown` independently. The unknown view keeps the uncertainty explicit and does not render an invented negative result, score or urgency.
- Tested both color schemes and `prefers-reduced-motion`. The reduced-motion transition duration resolved to zero. Focus-visible styling is present on search and filter controls.
- Measured the small metadata foreground tokens against their actual theme surfaces after the review: the light `faint` token is 4.97:1 against canvas and 5.44:1 against paper; dark mode's token is 5.68:1 against the dark canvas and 5.23:1 against the dark panel. They now meet 4.5:1 for normal text on those surfaces.
- Print emulation showed zero scripts, hid workspace chrome and contents navigation, and retained all 18 evidence rows; the rows use `content-visibility: visible` in print.
- Checked report build output with the existing script gate: no inline or external JavaScript, no unsafe citation URLs, correct `noindex` fixture metadata, actual report counts and resolvable local publication links.

## Performance comparison

Measurements compare `origin/main` and the redesign, each served locally with the same fixture harness. Chromium used a 1440 × 1000 viewport, browser cache disabled, five cold navigations per route, no CPU/network throttling, and a 2.2 second post-navigation observation window. FCP/LCP are local lab timings; they are not field data or production Core Web Vitals.

| Route | Measure | `origin/main` median | Redesign median | Difference |
| --- | --- | ---: | ---: | ---: |
| Live Feed | FCP / LCP | 288 / 288 ms | 240 / 240 ms | −48 / −48 ms |
| Explore | FCP / LCP | 256 / 316 ms | 264 / 264 ms | +8 / −52 ms |
| Live Feed | DOMContentLoaded | 73.0 ms | 62.0 ms | −11.0 ms |
| Explore | DOMContentLoaded | 55.5 ms | 65.6 ms | +10.1 ms |
| Explore | Initial route resource transfer | 722,988 B | 711,030 B | −11,958 B (−1.7%) |
| Live Feed | Initial route resource transfer | 686,150 B | 699,657 B | +13,507 B (+2.0%) |

The five LCP samples ranged from 260–332 ms to 228–292 ms for Live Feed and 284–360 ms to 232–308 ms for Explore; those ranges overlap. The medians are useful as a lab comparison, not proof of a field improvement. The initial route resource transfer includes the local API fixture, font and browser per-request overhead; the server does not model production compression, CDN caching, internet latency or CPU contention. Across built SPA JS+CSS assets, uncompressed size moved from 686,454 B to 695,023 B (+8,569 B / +1.25%). Gzip-9 size moved from 204,828 B to 205,981 B (+1,153 B / +0.56%). JS alone fell by 1,165 B raw and 856 B gzip-9; CSS grew by 9,734 B raw and 2,009 B gzip-9. The redesigned Explore route no longer loads the previous inline dossier components, while the shared responsive visual system adds CSS. No blanket performance improvement is claimed: the measured local navigation medians are mixed, the CSS payload is larger, and Live Feed's total initial route bytes increased.

The visible reading improvement is structural: in the matched article fixture, the original summary begins near y=722 and the substantive analysis starts below the 1000 px viewport. The redesign moves “read first” to about y=392 and starts the first claim section with evidence references around y=560. This is a rendered screenshot comparison, not a Core Web Vital.

## Build and release verification

Local checks completed against this branch:

- `ui`: `npm run typecheck`, `npm run build` — passed; Quasar targets `baseline-widely-available`.
- `edge/frontend`: `npm ci`, `npm run typecheck`, `npm run build`, `npm test` — passed (10/10 routing and release tests); `npx cf workers versions create --dry-run --prebuilt --mode production` — passed without uploading a version.
- `reports/site`: `npm ci`, `npm run test:cve-fact`, `npm run build` — passed. Rich v2 article fixture checks passed. Empty checked-in publication content produced the existing expected Astro empty-collection warnings; the synthetic article was built separately for rendered verification.
- CI contracts: `python -m unittest discover -s tests/ci -v` — 4 passed. Six report JSON schemas passed `Draft202012Validator.check_schema`; Astro local-link check passed for both emitted pages.
- Python release checks triggered by the report changes: source lint and registry validation passed; migrations to head and to the CVE-role test revision passed; `pytest -q` reported 224 passed, 30 skipped and 14 subtests passed; snapshot output reported `0013|0|0|0|0|0|0|0|none` and restored the `sources` table; CVE/KEV, EPSS and append-only event grant verification passed.
- The official report Worker image uses Docker. A local build could not complete in this environment: the standard attempt hit its untrusted TLS proxy, and a retry with a temporary BuildKit CA secret later ran out of Docker overlay/cache space during optional Codex CLI package extraction. GitHub Actions subsequently built the image and passed its read-only-rootfs, 128 MiB `/tmp` production smoke test. The local limitation did not block the verified CI release gate.

GitHub Actions PR run [43663834446](https://github.com/yohn-jp/nous-osint/actions/runs/43663834446) passed on the corrected branch revision: `changes`, `ci-contracts`, `check`, `cve-role-grants`, `frontend`, `reports`, `report-worker-image` and aggregate `ci` all succeeded. The report Worker image was exercised under a read-only root filesystem and the production tmpfs limits. The first run caught a missing `rel="noopener noreferrer"` on the article's canonical CVE link; the follow-up fix added that attribute and a generated-HTML regression assertion, and the complete run then passed. `terraform`, `frontend-deploy` and `image` were skipped by the PR workflow; no deployment, merge or report release promotion was performed.
