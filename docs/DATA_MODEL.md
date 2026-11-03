# Nous OSINT — Data and Source Contracts

Status: **implemented through Alembic 0005**  
Updated: 2026-11-03

## 1. Data ownership

- **Git** stores reviewed **official catalog** source declarations (`sources/*.yaml`), connector code, schemas and migrations.
- **PostgreSQL** stores effective official configuration with local overrides, custom source definitions, admin audit history, execution state, jobs, observations, normalized items and their versions.
- **Private VM storage** may hold temporary raw responses when permitted, with fixed TTL. No arbitrary crawled payload is committed to Git.
- **Exports** are opt-in, fact-oriented, and omit copyrighted text, private information, keys and unreviewed AI assertions.

## 2. Declarative source format

Planned shape (illustrative YAML schema, not an implemented parser):

```yaml
id: example-security-feed
kind: rss                 # rss | json_api | html
url: https://example.org/public-feed.xml
adapter: rss_v1
interval_minutes: 120
max_requests_per_hour: 12
max_concurrency: 1
enabled: false            # examples must not run by default
policy:
  reviewed_at: null
  terms_url: null
  robots_url: null
  content_storage: metadata_only
  note: "Placeholder: replace with an approved real source"
```

Source IDs are immutable, unique and human-readable. Official entries are seeded from Git; custom entries are created in the per-instance Admin UI. An official ID conflict is rejected; source removal preserves historical observations. Registration validation rejects duplicate IDs, invalid protocols, unsupported adapters, unreviewed collection policies and unsafe endpoints. A disabled source remains queryable, retaining its historical observations. Credentials are referenced by secret names, not values.

Every enabled source must define a reviewer-verifiable collection policy, ownership, rate limits and a positive decision to collect. A source is never enabled solely because an URL is reachable.

## 3. Core SQL entities — MVP

| Table | Purpose | Required constraints |
| --- | --- | --- |
| `sources` | Official catalog + custom source identity, per-instance overrides and execution state | unique `source_key`; `enabled`; `config_revision`; `last_success_at`; `next_due_at` |
| `fetch_jobs` | Durable scheduled work + claim lease | unique `dedupe_key`; `state`; `available_at`; `lease_until`; attempt count |
| `fetch_attempts` | Append-only evidence of each network/parse attempt | `job_id`, start/end, outcome, status, final URL, error code |
| `items` | Stable identity of a publisher record | `source_id`, `external_id` or verified canonical URL, `kind`, `first_seen_at`, `last_seen_at`, state |
| `item_versions` | Immutable observed changes | `item_id`, sequential version, `observed_at`, `sha256`, attributes, provenance |

Required item types initially: `job_posting`, `news`, `advisory`, `vulnerability`, `company_update`. A connector maps source-native fields into this shared vocabulary, preserving source-native keys in a validated namespace.

### Identity and history rules

- A source's stable published ID is preferred; otherwise use a carefully normalized canonical URL. Different sources may legitimately publish the same URL; cross-source deduplication is a separate, attributed operation.
- Persist `source_id + stable_external_id` as a unique record identity, with fallback URL uniqueness for records lacking IDs. An item retains its identity across title/body changes.
- Define the hash input **per adapter version** using a deterministic canonical serialization of relevant fields; timestamps of polling, tracking parameters and transient page chrome must not trigger new versions.
- Store a new `item_versions` record only when that hash changes. Preserve previous revisions; never overwrite history.
- Keep original values alongside normalized timestamps, currencies and enums. A null/unknown value is not inferred as absent or zero.
- Record `published_at` and `updated_at` when supplied by the publisher, separate from system `first_seen_at`, `last_seen_at` and `observed_at`.
- Item disappearance does not imply deletion or vacancy closure. Explicit source evidence or a versioned connector rule is needed for `closed`; otherwise mark `stale/unknown`.

### Provenance fields

Each version must identify `source_id`, fetched URL/final URL, retrieval time, adapter identifier/version and content fingerprint. Derived assertions include `extraction_method` (source field, deterministic parser, external enrichment or AI), `evidence_locator` and `verification_state`. This avoids representing model-generated inferences as confirmed publisher facts.

### Transaction discipline

A claimed job has a finite lease. A worker commits the lease and releases the transaction **before** outbound HTTP. The observation write and job completion are performed atomically where possible. Crashes may cause repeat work; uniqueness and deterministic hashes must make that safe.

`fetch_attempts` and `item_versions` are append-only. Retention pruning, when permitted, is an explicit maintenance operation with its own audit record.

## 4. Later relational layer (not MVP acceptance)

- `entities`: `organization`, `product`, `technology`, `vulnerability`, `job_role`.
- `item_entity_links`: where a source item mentions or asserts an entity, with evidence.
- `relations`: typed links between entities, source-backed or explicitly marked as inferred.

Entity resolution is conservative. Similar company names or products are not enough to merge automatically. Schema changes must be Alembic migrations; migrations run as a one-off operational action, never concurrently in all app containers.

## 5. API contracts — first iteration

- `GET /health/live` — application process responsive.
- `GET /health/ready` — DB connection/migrations ready.
- `GET /v1/sources` — enabled state, last success, lag, error class.
- `GET /v1/items?kind=&source=&q=&since=&limit=&cursor=` — paginated current items; cursor-based stable ordering.
- `GET /v1/items/{id}` — current item plus source, timestamps and provenance.
- `GET /v1/items/{id}/versions` — revision history.
- `GET /v1/changes?since=&kind=` — newly observed and changed records.

Public read responses remain bounded and omit secrets or unlicensed full text. The separate Access-authorized gateway exposes limited `/v1/admin/*` source management with audit tracking; MCP and normal query routes remain read-only. See [Source Management](SOURCE_MANAGEMENT.md).

## 6. Quality criteria

1. Repeated fetch of an unchanged RSS item does not create a new item or version.
2. Publisher modification creates exactly one new version under concurrent re-fetch.
3. Cross-source collisions do not destroy either source's provenance.
4. 304, 429, timeout, malformed data, redirect and source removal have distinguishable outcomes.
5. Every displayed fact resolves to source URL, observation timestamp and extractor version.
6. Export and API responses exclude private data and unlicensed article bodies by default.
