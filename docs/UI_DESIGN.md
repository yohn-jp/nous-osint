# Nous OSINT — Interface design contract

Updated: 2026-11-15<br>
Status: redesign candidate on `feat/ui-redesign-v2`; see [redesign evidence](ui-redesign/README.md). This is a product design and implementation contract, not evidence of a production deployment.<br>
Architecture authority: [ARCHITECTURE.md](ARCHITECTURE.md), [FRONTEND_EXECUTION_POLICY.md](FRONTEND_EXECUTION_POLICY.md), [EDGE_FRONTEND_DEPLOYMENT.md](EDGE_FRONTEND_DEPLOYMENT.md), [AUTOMATED_INTELLIGENCE_REPORTS.md](AUTOMATED_INTELLIGENCE_REPORTS.md).

## Product model

Nous connects three daily jobs: monitor newly collected information, investigate a record and its provenance, and read published intelligence. Research records are the primary objects in the SPA; published reports are first-class reading surfaces. The interface must make the path between those jobs legible without pretending that collection state, KEV state, claim classification, and publication state are interchangeable.

The selected direction is a light, warm-paper research register with deep-green navigation, restrained copper editorial markers and blue evidence links. It uses chronological observation groups for Live Feed, a full-width searchable record index for Explore, a dedicated record dossier, and an editorial report archive and article. The report page opens directly on the report title and conclusion summary, then connects sectioned analysis to numbered claims and a source register. It does not use an oversized cover or dashboard-style provenance cards.

Two high-fidelity directions were compared. Direction A makes the observed record or article the visual anchor and keeps contextual detail one action away. Direction B, “Signal Room,” uses a dark two-column feed and persistent source-health rail. B presents source health prominently, but repeats status alongside the timeline and competes with the information being investigated. A better supports continuous scanning and publication reading, so it is the selected direction. See the [direction B prototype](ui-redesign/direction-b-signal-room.html), its [screenshot](ui-redesign/screenshots/direction-b-signal-room.png), and the before/after captures in the [redesign evidence](ui-redesign/README.md).

## Surface and interaction contracts

### Monitoring and investigation

- **Live Feed** is an observation timeline grouped by actual Tokyo-local date and time. Each entry identifies its source, content kind/category and real record state. Refreshes do not silently reorder the user's current context: newly arrived records are announced in a pending count until requested. Filters live in the URL; pagination remains bounded.
- **Explore** is a full-width index with compact search and category, kind and source filters. Its row hierarchy favors title, source identity and observed/published time, then explicit state and version. `/` focuses search; `j`/`k` and arrows move through records when the register is active. IME composition is respected. Query filters survive reload and return navigation.
- Selecting a record opens a **dossier route** rather than replacing part of the index. It presents source identity, publisher link, observed and published times, current immutable version, attributes, provenance and observation history. A validated internal `returnTo` restores Live Feed, Explore, Changes or CVE context and its query. Publisher links are URL-sanitized and open with `noopener noreferrer`.
- **Changes** remains a view of observed revisions across the existing time ranges. It does not imply unobserved chronology or fabricate a diff.
- **Sources** and source administration keep configuration, successful collection, recent collection error and unknown state distinct. Operational status derives from API data, not the enabled flag alone.
- **CVE / KEV** preserves `listed`, `not_listed` and `unknown` as three different states. A mention is not catalog confirmation; unknown is not shown as a negative result. No urgency, severity or intelligence score is invented.

### Reports and publication

- **Archive** lists real published reports, with category, publication date, title, deck, evidence and claim-classification counts. Empty or sparse publication content remains sparse; fixtures are not shipped as live reports.
- **Article** uses Japanese reading typography, an immediately visible concise opening, a substantive “read first” summary, numbered sections and an intuitive contents rail. Claim classification and evidence IDs are close to the claim text. The source register provides source identity, publisher, captured/published times and relation metadata. Links connect claims to evidence and back to the report archive or research workspace.
- The static Astro renderer remains script-free. Article navigation and evidence references use normal anchors and document landmarks; print removes application chrome while retaining report text and source metadata. The SPA shell and publication shell share visual tokens and navigation roles, while keeping their runtime and security responsibilities separate.
- Report schema versions supported by the existing renderer remain supported. New visual presentation does not alter report JSON, provenance, public release paths or the renderer fingerprint / atomic promotion workflow.

### Administration

Source configuration, collection outcomes, report runs and schedules have explicit tasks and state labels. For report runs, configuration and ad-hoc execution are separate from execution history and event detail; schedule controls remain a separate operational task. Queued, leased, running, validating, publishing, published, failed and unknown states remain distinguishable. Counts are from the loaded API page, not estimated totals. Existing role checks remain server-side and unchanged.

## Visual and responsive system

- Vue 3, Quasar and TypeScript remain the SPA stack; Astro remains the static report stack. Shared paper, ink, green, copper and evidence-link tokens align both renderers without coupling their runtimes.
- Layout composition changes at component and viewport widths. Fluid type and spacing use `clamp()`, CSS Grid/Flexbox, logical sizing and `@container` where a component's available width matters. Dense filters collapse to usable stacked controls on narrow screens. Japanese text, identifiers and source titles wrap without page-level horizontal overflow.
- Focus is visible on controls and full rows; status meaning is present in text as well as color. Native links and buttons retain keyboard behavior. Reduced-motion preferences disable transitions. Print styles hide workspace navigation and preserve report content.
- Live Feed and Explore records are kept in normal rendering flow because they are simple, scannable content. Deferred rendering is limited to the below-fold article evidence register, with intrinsic-size reservation and normal keyboard access.
- Screenshots and the direction comparison use a synthetic 18-claim/18-source report fixture with observed fact, inference and unconfirmed classifications. The fixture is under `reports/site/test-fixtures/`, excluded from the published content collection.

## Data, architecture and security invariants

- Research uses the existing same-origin `/v1` API and bounded cursor pagination. The redesign does not add a client credential, alter API schemas or change claim/source semantics.
- Observation history is immutable. Item return paths are allowlisted internal paths; publisher destinations pass the existing URL safety rules.
- Administrative endpoints retain independent role authorization. Frontend navigation or presentation is not an authorization boundary.
- Static SPA hosting remains isolated from `/v1/*`, `/mcp*`, OAuth and the private `/reports/*` origin. The Cloudflare Worker/Tunnel split is unchanged; no catch-all forwarding is introduced.
- Published output remains sanitized, script-free HTML generated by the Astro renderer. CSP, trusted renderer fingerprinting, content-addressed release assets, validation and atomic release promotion remain intact. No external scripts, runtime CSS or browser-side report data fetching are added.

## Verification record

Automated build and fixture results, rendered browser walkthroughs, screenshot evidence, resource-size comparison, limitations and Modern Web Guidance references are maintained in [docs/ui-redesign/README.md](ui-redesign/README.md). Those local checks do not claim production Core Web Vitals, authenticated Cloudflare Access behavior, remote origin routing, image promotion or rollback. No merge or deployment is part of this design contract.
