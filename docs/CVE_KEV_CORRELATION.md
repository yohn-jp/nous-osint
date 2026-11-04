# CVE ↔ CISA KEV correlation

Implementation: `cve_item_links` / Alembic **0007**, `GET /v1/cves/{cve_id}`,
`get_cve` (read-only MCP) and the private UI `/cves/CVE-YYYY-NNNN`.

## Authority and interpretation

CVE is the stable **identifier**; KEV membership is an assertion made by
CISA's **Known Exploited Vulnerabilities** catalog. They are not two competing
identifiers. Cross-source joins use the exact canonical CVE ID, with no title
similarity, product-name inference or invented link to an unrelated CVE.

Nous preserves every publisher's `items` and immutable `item_versions`.
`cve_item_links` contains the *current* relationships
(`item_id`, `cve_id`, `relation`), indexed by CVE ID:

| Relation | Evidence | Implication |
| --- | --- | --- |
| `kev` | Only structurally validated `cisa_kev_v1` records | CISA has listed the CVE as known exploited |
| `record` | Native structured `vulnerability.cve_id` or exact JSON CVE record ID | Exact CVE record identity, **not** an exploitation claim |
| `reference` | Explicit validated `cve_ids` array in a source observation | Publisher refers to this CVE |
| `title_mention` | Case-sensitive exact CVE ID in a publisher's title | Mention alone; **not** a CVE disclosure or exploitation finding |

The canonical CISA KEV source is `cisa-kev`, maintained in Git and distributed
**disabled by default**. Other sources cannot assert KEV membership through
title wording or matching a vendor/product name. Link updates and version
history commit in the same PostgreSQL transaction. A title losing a CVE mention
removes the *current* link without erasing its earlier recorded versions.

The migration backfills exact CVE identifiers from existing vulnerability/
advisory items and title mentions from existing items. It does not rewrite
historical source data or re-fetch publisher content.

## API semantics

Example request: `GET /v1/cves/CVE-2026-12345`.

The response separates `cve_id`, `canonical_url`, `kev` and
`references`. References include individual source IDs, source URLs,
the item ID, current state, observed timestamp, evidence grade and the source
adapter; the list is bounded to 50 records and signals truncation.
The canonical CVE.org URL is an **identifier lookup**; it is not represented
as CISA's source of the exploitation determination.

KEV has exactly three states:

- **`listed`**: a current, source-backed item from the official
  `cisa-kev` catalog exists. The response carries the CISA publisher URL,
  date added, due date, vendor/product, ransomware-use flag and last successful
  catalog fetch. Even a stale positive assertion retains its observation time.
- **`not_listed`**: no active CISA KEV item exists *and* the full official
  catalog was successfully fetched within the previous **48 hours**.
  This means “not listed in the last successfully observed catalog,” **not**
  “not exploited.”
- **`unknown`**: no relevant CISA catalog has been successfully ingested
  recently enough to justify absence. The first install, a disabled/uncollected
  source and an outdated complete snapshot produce `unknown` when the CVE
  is absent.

The CVE endpoint returns a legitimate empty result with `unknown` for an
unknown ID; it never initiates an outside HTTP request or assumes a CVE record
exists simply because the ID is syntactically valid. The same bounded payload
is exposed as read-only MCP `get_cve(cve_id)`, without enabling remote writes.

## Security, source rights and operations

- CISA's **KEV dataset** is [CC0-1.0](https://github.com/cisagov/kev-data).
  External links, vendors' article text and official logos have separate
  rights; Nous's MIT source-code license does **not** license them.
- Requests pass through the existing signed Cloudflare Access verification,
  known GET route allowlist, query-key filtering and `Cache-Control: no-store`.
- The public data API and MCP are read-only; only the existing scheduler/worker
  writes link associations. The Admin UI cannot forge or override KEV status.
- Apply `alembic upgrade head` (0007) before deploying the corresponding
  application image. The health readiness check rejects mismatched schema.
- Enabling `cisa-kev` still requires live probe, rights review, and explicit
  operator activation. No production activation is implicit in this PR.

## Boundaries

This change indexes the CVE identities already present in Nous, including the
CISA KEV catalog and other publisher record titles. **It does not claim a full
official CVE List ingestion or NVD enrichment**. Those require a separate,
bounded CVE JSON 5 / NVD adapter with pagination, incremental update state,
rights review and source provenance. When those observations are added, they
join the same CVE identifiers without confusing NVD analysis, CVE Program
publication or CISA exploitation evidence.

Primary sources:
[CISA KEV dataset](https://github.com/cisagov/kev-data);
[CVE Program's official CVE List V5](https://github.com/CVEProject/cvelistV5).
