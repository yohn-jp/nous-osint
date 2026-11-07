# Adapter selection — first-party security intelligence and Japanese security hiring

Research baseline: **2026-11-04**. This document distinguishes native adapters present in main from candidate connectors not yet implemented.

## What current adapters can do

- `rss_v1` uses the existing OSS `feedparser` to extract absolute publisher
  titles, item links and timestamps from RSS/RDF/Atom. It does not ingest
  attachments, articles, CVE objects or rights-bearing full text.
- `json_v1` extracts a **single** JSON list or a dotted list path and maps
  flat item identity, URL, title and timestamps. It does not paginate,
  normalize nested ATS fields, synthesize absent URLs or perform delta sync.
- `html_v1` uses `BeautifulSoup` and declarative selectors, without a
  browser or cross-page crawl. Site-specific scripts are discouraged.

The catalog addition includes nine disabled candidates. On main, `sie-japan-careers` now uses `greenhouse_jobs_v1`, filtering for
explicitly Japan-based security roles. `lever_jobs_v1` and `ashby_jobs_v1`
are available for per-instance Admin UI registration without shipping
hypothetical company board URLs. The filtering is deterministic, conservative
and records its location/title/department evidence.

Lever pagination uses the production SSRF-safe HTTPX fetcher with bounded
requests and explicit page-budget accounting; partial boards are never
committed. This intentionally does **not** instantiate a separate dlt
HTTP session or a second data pipeline. Dlt RESTClient remains the candidate
for NVD and more complex cursor-based APIs after an adapter can preserve the
verified-address fetch boundary and job-state transactions.

## Proposed OSS stack

| Task | OSS choice and license | Decision |
| --- | --- | --- |
| REST API pagination, retry, incremental windows | [dlt RESTClient/REST API source](https://dlthub.com/docs/dlt-ecosystem/verified-sources/rest_api) — **Apache-2.0** | Evaluate for NVD, Lever and other paginated feeds; use only the extraction layer if Nous's SQL/history remains authoritative |
| HTTP, TLS transport and SSRF policy | Existing [HTTPX](https://www.python-httpx.org/) with Nous's pinned-address safe fetch | Retain the existing trusted network boundary, timeouts, redirect and response-size limits; never delegate untrusted arbitrary URLs to a second permissive downloader |
| Static HTML crawling when necessary | [Scrapy](https://github.com/scrapy/scrapy) — **BSD-3-Clause** | Prefer for multiple-page public recruiting sites that offer neither RSS nor a published API; use robots, per-site rate limits and allowlisted hosts |
| JS-rendered public careers pages | [scrapy-playwright](https://github.com/scrapy-plugins/scrapy-playwright) — **BSD-3-Clause**, [Playwright](https://github.com/microsoft/playwright-python) — **Apache-2.0** | Opt-in only after proving the official API/static HTML cannot supply the data; isolate memory/CPU, no login/CAPTCHA/anti-bot bypass |
| Alternative single-stack HTTP+browser crawler | [Crawlee for Python](https://github.com/apify/crawlee-python) — **Apache-2.0** | Consider *instead of* Scrapy, not alongside it, if browser-native orchestration becomes necessary; forbid fingerprint impersonation and proxy evasion |

We should **not** install Scrapy, Crawlee and dlt together before the
required adapters are known. Each adds dependencies, runtimes or state
machinery; none may bypass Nous's SSRF, source rate controls, scheduling,
lease, source provenance or licensing boundaries. Prefer one bounded
connector implementation per source family.

## Priority A — Japanese security positions

1. Reuse published ATS APIs where possible:
   - Greenhouse Job Board API: a `jobs` list with `id`, `title`,
     `absolute_url`, nested `location.name`, departments/offices.
   - Lever Postings API: `id`, `text`, `hostedUrl`, `country`,
     `categories`, with documented `skip`/`limit` pagination.
   - Ashby public Job Postings API: `jobs`, `title`, `jobUrl`,
     `location`, `department`, `employmentType`, `isListed`.
2. Use a **typed job normalizer** shared across ATS products. Persist
   posting ID, origin, employer, titles (Japanese/English), country,
   structured location, job category, posted/updated time, source URI,
   classification evidence, last-seen state and raw-field provenance.
   Do **not** store descriptions by default.
3. Add a deterministic `Japan AND security function` filter after the
   data-source mapping; fields such as `country == JP` outrank
   keyword-only inferences. Do not discard ambiguous/unclassified roles
   without preserving a reason. Treat security-vendor sales vs security
   architecture/engineering as separate classifications.
4. Do not infer a closed job from its disappearance after a failed,
   partial, rate-limited or paginated sync. Require complete successful
   enumeration (or authoritative closure) before changing job state.
5. For HRMOS/HERP and company-built boards, first verify any supported
   publisher API/JSON-LD/embedded structured data; otherwise choose a
   bounded static crawler with selectors. A browser is the final fallback.

The SIE Japan Greenhouse board remains disabled. The native adapter is present,
but live extraction and publisher rights still require independent validation.

Publisher documentation:
- https://docs.greenhouse.io/job-board
- https://github.com/lever/postings-api
- https://developers.ashbyhq.com/docs/public-job-posting-api

## Priority B — global vulnerability data

1. **CISA KEV — implemented in stacked vulnerability PR**: the dedicated
   `cisa_kev_v1` adapter uses the CISA-maintained GitHub mirror
   (CC0-1.0). It validates `count`, duplicate CVE IDs and bounded
   metadata before any DB writes, and creates stable canonical CVE links.
   The source is distributed disabled; neither live probe nor deployment
   is claimed. Its publisher is linked in item provenance.
2. **NVD API 2.0**: pagination, `lastModStartDate/lastModEndDate`,
   reasonable API-key handling, retry limits and nested vulnerability
   extraction. Use the OSS REST paging layer where it meets bounded
   fetch/SSRF constraints.
3. **CVE List V5 and OSV**: use their official versioned JSON feeds and
   deltas. A repo/ZIP snapshot is not an RSS entry; implement a separate
   bulk source backed by deterministic cursors and bounded unpacking.
4. **FIRST EPSS**: score snapshots attach to CVEs. Store as
   time-indexed enrichment, not fabricated new article records.
5. Identity and merging: preserve individual source assertions separately,
   relate by CVE identifier, and retain provenance and revisions.
   Do not conflate a NVD analysis date with a source's original publish date.

## Non-negotiable integration contract

- One scheduler, one worker lease authority and one historical data model;
  no independent Scrapy/dlt database that silently becomes the system of
  record. OSS workers must return bounded structured observations.
- Never bypass HTTPS global-address checks, DNS pinning, redirect recheck,
  host concurrency, rate limits, robots/terms constraints and body caps.
  Standard Scrapy/Playwright defaults do not establish these constraints.
- Per-source cursor and completeness must be committed with the corresponding
  observation transaction; a crash after fetch must not mark unprocessed
  pages as complete. Stable source IDs and deterministic content hashes.
- New adapters are allowlisted by registry schema, and disabled candidates
  must be probeable without starting live ingestion.
- Keep credential storage outside Git and Admin UI. Do not use residential
  proxies, CAPTCHA bypass, login circumvention or browser fingerprint
  tricks in the official package.

## Recommended implementation sequence

**Implemented (stacked PR):** Greenhouse, Lever and Ashby metadata
normalization, Japan/security filtering, verified official endpoints,
bounded Lever paging, and in-instance custom source registration. HTTPX,
Pydantic, JSON and the existing PostgreSQL scheduler are reused. No extra
scraping framework is necessary for publisher-provided native APIs.

**Next:** build NVD cursor-based/incremental collection with an audited
request budget and persisted continuation state; then CVE List and OSV
full/delta sources with separate EPSS enrichment. CISA KEV is now
implemented as a safe whole-snapshot feed, using the existing OSS HTTPX
transport and Pydantic/standard JSON validation.
Assess the dlt RESTClient only where its pagination/cursor support can be
integrated without bypassing the existing safe fetcher.
**Later:** adopt Scrapy for selected approved HRMOS/HERP HTML pages that
have no supported feeds, JSON-LD or published APIs; Playwright only if
static parsing cannot work. Each phase retains the canonical scheduler,
security contract and history.
