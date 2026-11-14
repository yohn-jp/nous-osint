# Nous OSINT workstation modernization

This change completes a focused pass over the existing Vue 3 / Quasar research app and the independent Astro publication renderer. It follows the accepted UI contract in [`docs/UI_DESIGN.md`](../UI_DESIGN.md) and the runtime and release boundaries in [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md), [`docs/FRONTEND_EXECUTION_POLICY.md`](../FRONTEND_EXECUTION_POLICY.md), and [`docs/EDGE_RELEASE_PIPELINE.md`](../EDGE_RELEASE_PIPELINE.md).

The screenshots and browser checks use local synthetic API responses and the repository's published-report fixtures. They contain no authenticated production data.

## Layout choice

Two layouts were compared against the existing design contract.

| Approach | Benefit | Cost |
| --- | --- | --- |
| Dense record register with an adjacent inspector at desktop widths | Keeps selection, comparison, source, and history in the same URL-backed workspace | The inspector narrows the register around the 1200 px breakpoint |
| Editorial single-column feed with a separate detail page | Gives each record a wide reading column | Breaks the established register-and-inspector flow and makes comparing evidence require repeated navigation |

The register and inspector remain the desktop layout because they preserve the accepted source-first workflow and URL state. A container query now changes the register itself when its available width becomes narrow: publisher and observation time move under the title, while status stays visible. Below 1200 px, the app continues to use the full-width register and the existing record detail route.

## Changes

### Research application

- The register adapts to its own width, including when the inspector is open at 1200 px. Publisher and time are still visible beside the record; status and version remain distinct.
- Publisher and lifecycle context appear as compact, wrapping metadata, with a semantic `<time>` for publication or last observation.
- The register scroll region has an accessible name and keyboard focus. Closing the inspector returns focus to its selected record, or to the register/search when that record is outside the loaded cursor page. J/K navigation starts from the focused row, and Escape closes the inspector while preserving that row focus.
- Filter changes remain URL-backed. Changing only the selected `item` no longer refetches the list; the watcher now tracks the four filter values separately. Existing abort handling remains in place for real filter changes.
- Layout and paint containment keep a 40-record page inside the register's scrollport instead of extending the document with a large blank tail.

### Publications and provenance

- The report contents navigation is a horizontal list rather than inheriting the legacy two-column article outline. The source-register return link fits narrow screens.
- Astro and Quasar retain separate runtimes but share the publication palette through CSS tokens. The article cover, executive brief, claim classifications, CVE/KEV context, and evidence ledger remain the established provenance dossier.
- The archive uses `content-visibility: auto` for entries after the first eight, with an intrinsic size for off-screen layout. The first entries remain immediately rendered.
- Empty archive copy describes the absence of a published report without implying a collection or publication failure.
- The report article remains static and script-free. Evidence anchors, publisher links, archive return, and research-feed return remain native document navigation.
- The report fixture test continues to build both supported article schemas and rejects a mismatched deterministic CVE fact.

The source manager, report execution history, and schedule controls continue to display configured, enabled, collected, failed, published, and unknown values from their existing API fields. No operational state or severity score is inferred from missing evidence.

## Screenshots

These captures show the baseline and the implemented UI. The after set includes both sides of the 1200 px layout breakpoint, the record detail route, and a print rendering. The separate browser check stress-tested a dossier with 30 evidence entries at mobile widths.

| Surface | Before | After |
| --- | --- | --- |
| Research register and inspector | [1440 px](screenshots/before/research-explore.png) | [1440 px](screenshots/after/research-explore-1440.png), [1200 px](screenshots/after/research-explore-1200.png), [1199 px](screenshots/after/research-explore-1199.png) |
| Sources and operational state | [Sources](screenshots/before/sources.png) | [Sources](screenshots/after/sources.png) |
| CVE / KEV evidence | [CVE / KEV](screenshots/before/cve-kev.png) | [CVE / KEV](screenshots/after/cve-kev.png) |
| Record details and provenance | [Selected-record inspector](screenshots/before/research-explore.png) | [Record route at 1199 px](screenshots/after/record-provenance-1199.png) |
| Report archive and dossier | [Archive](screenshots/before/report-archive.png), [article](screenshots/before/published-report.png) | [Archive](screenshots/after/report-archive.png), [article](screenshots/after/published-report.png) |
| Report administration | [Run history](screenshots/before/report-administration.png) | [Run history and failure detail](screenshots/after/report-administration.png) |
| Mobile research and navigation | [390 px](screenshots/before/mobile-research.png), [navigation](screenshots/before/mobile-navigation.png) | [320 px](screenshots/after/mobile-research-320.png), [390 px](screenshots/after/mobile-research-390.png), [navigation](screenshots/after/mobile-navigation.png) |
| Mobile article and print | [320 px article](screenshots/before/report-mobile-320.png) | [320 px](screenshots/after/report-mobile-320.png), [390 px](screenshots/after/report-mobile-390.png), [print](screenshots/after/report-print.png) |

## GoogleChrome Modern Web Guidance

Guidance was searched and retrieved with the official `modern-web-guidance` CLI from [GoogleChrome/modern-web-guidance-src](https://github.com/GoogleChrome/modern-web-guidance-src). No guidance tooling was added as a runtime dependency. The final deterministic `legacy-scan` reported **0 findings across 33 qualified guides**; this scan covers only part of the guidance corpus.

| Retrieved guidance ID | Decision and code application |
| --- | --- |
| `responsive-table` | Container-query the research register at 820 px of available width; retain record and state, and move duplicated publisher/time context into the record cell. |
| `css-layout` | Use a named inline-size container for the register; explicitly set the dossier contents nav to `display: block` so the older `.article-outline` grid cannot collapse it. |
| `responsive-design`, `form-factor-adaptation` | Keep viewport breakpoints for navigation and the 1200 px inspector transition, with container sizing for the narrower register inside that desktop layout. |
| `single-line-overflow`, `typography` | Allow Japanese titles and metadata to wrap in the register and source return link; use a semantic `<time>` for date context. |
| `interactions-in-complex-layouts`, `accessibility`, `html` | Name the scrollable record region, retain the table caption and native anchors, and restore focus to the selected row after inspector close. J/K derives its current row from actual focus. |
| `performance` | Add layout and paint containment to the scrollport. In the 40-record browser fixture, document height stays near the viewport instead of growing with all table rows. |
| `defer-rendering-heavy-content` | Apply `content-visibility: auto` to archive entries after the first eight. The research page is already bounded to 40 records per cursor page; the dossier keeps eager article-anchor and print layout. |
| `dark-mode` | Declare `color-scheme: light dark` on the Astro root, use shared masthead/brand palette tokens, and verify the dark palette in Chromium. The dark-mode declarations are scoped to the report's theme tokens. |
| `motion` | Keep the existing reduced-motion rules. Browser emulation verified zero transition duration and automatic scroll behavior. |
| `deprioritize-background-fetches` | Avoid an extra record-list request when only the inspector selection changes. Source lookup remains available for the visible filter controls. |
| `optimize-preload-priority` | No new preload or resource-priority hints were added: the static report has no images, web fonts, or scripts requiring priority changes. |

Subgrid and `scheduler.yield()` were not added: neither runtime has a demonstrated alignment or long main-thread task that needs them. The report renderer remains script-free.

## Verification

### Browser acceptance

A local Chromium run used the same 40-record synthetic API fixture for the SPA and a built Astro v1/v2 report fixture. It covered:

- 320, 390, 1199, 1200, and 1440 px viewports, with no horizontal document overflow. A long dossier containing 30 evidence entries also had no horizontal overflow at 320 and 390 px.
- Keyword and source filtering, the 40-to-80 cursor-page transition, URL state, selection, provenance attributes, immutable observation versions and SHA-256 values.
- Inspector focus return (including a selected record outside the loaded cursor page), J/K movement, Escape, and `/` search focus. Changing the selected row added no list API request.
- Source states for enabled/disabled configuration, prior successful collection, unconfirmed collection history, and distinct `feed_timeout` / `http_503` errors. Run failure stage, error code, schedule state, and published run were displayed from fixture values.
- KEV `listed`, `not_listed`, and `unknown` values as separate labels, plus empty and forbidden API states.
- Research-to-report navigation, citation-to-evidence navigation, the publisher link's `noopener noreferrer`, report-to-archive and report-to-research returns, mobile `returnTo`, and print media.
- Reduced motion and dark palette. The report output had zero `<script>` tags. No unexpected console, page, or non-API HTTP errors occurred; the one simulated API 403 was the expected permission-state case.

This is local browser acceptance with mocked API data. Authenticated access, production authorization, and Cloudflare routing were not tested.

### Build, fixture, and release checks

| Check | Result |
| --- | --- |
| `ui`: `npm run typecheck` | Passed |
| `ui`: `npm run build` | Passed, `baseline-widely-available` browser target |
| `reports/site`: `npm run test:cve-fact` | Passed for v1, v2, empty archive, and invalid CVE fixture paths |
| `reports/site`: `npm run build` | Passed. The no-content build emits the expected empty collection warning; report fixture builds produce both v1 and v2 pages. |
| `edge/frontend`: typecheck, build, and `npm test` | Passed; 10 routing and release tests passed. |
| `edge/frontend`: `npx cf workers versions create --dry-run --prebuilt --mode production` | Passed; offline Worker dry-run completed. No upload or deploy was performed. |
| `python -m unittest discover -s tests/ci -v` | Passed; 4 release-scope tests passed. |
| Modern Web Guidance `legacy-scan .` | Passed; 0 findings across 33 qualified guides. |
| Static publication script check | Passed; zero script tags in built archive and article fixture HTML. |

The Astro Worker build, fixture output, and Edge dry-run validate local artifacts and route contracts. They do not validate an authenticated browser session, live Cloudflare routes, Access/Tunnel policy, release promotion, rollback, or production deployment.

### Bundle and local browser measurements

Quasar bundle totals from the same build tool before and after:

| | Baseline | After | Change |
| --- | ---: | ---: | ---: |
| JavaScript, raw | 405.10 KB | 405.82 KB | +0.72 KB |
| CSS, raw | 265.27 KB | 265.60 KB | +0.33 KB |
| CSS, gzip | 44.71 KB | 44.75 KB | +0.04 KB |
| HTML, raw | 0.54 KB | 0.54 KB | unchanged |

Astro's shared CSS changed from 64,957 bytes raw / 12,156 bytes gzip to 65,030 bytes raw / 12,211 bytes gzip. The static output contains 0 script tags before and after.

A Chromium local-harness comparison used 8 samples per build at 1440 × 1000, alternating baseline and after, after one warm-up per server. Both used the same 40-record synthetic API fixture and no network throttling.

| Median metric | Baseline | After |
| --- | ---: | ---: |
| First Contentful Paint | 684 ms | 662 ms |
| Largest Contentful Paint | 684 ms | 662 ms |
| DOM Content Loaded | 215 ms | 200 ms |
| Load event | 303 ms | 289 ms |
| First record visible | 780 ms | 783 ms |
| JavaScript resource transfer | 317,397 B | 318,136 B |
| CSS resource transfer | 267,073 B | 267,415 B |

The local medians are effectively flat at this scale: FCP/LCP were 22 ms lower and first-record visibility was 3 ms higher after the change. The transfer increase is 1,081 bytes across JS and CSS. This local, unthrottled fixture run is not a Core Web Vitals or production-network claim.

## Not checked

- Authenticated browser acceptance against the live API and real role/authorization responses.
- Cloudflare production routes, Access/Tunnel behavior, remote release promotion or rollback.
- Production deployment. No deployment or publication was performed.
- Backend `ruff` and `pytest` suites; this branch changes only the SPA, Astro presentation, and evidence documentation. GitHub PR CI is reported on the pull request after its checks run.
