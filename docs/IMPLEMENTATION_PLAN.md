# Nous OSINT — Implementation Plan and Acceptance Criteria

Status: **Phases 1–3 implemented in main in part; VM/real Codex acceptance still incomplete**  
Updated: 2026-11-05

Implementation authority: [ARCHITECTURE.md](ARCHITECTURE.md), [DATA_MODEL.md](DATA_MODEL.md), [QUADLET_DEPLOYMENT.md](QUADLET_DEPLOYMENT.md).

## Phase 0 — Architecture

- [x] Document single-VM rootless Podman/Quadlet topology and ownership boundaries.
- [x] Define initial ingestion/data provenance contracts and security posture.
- [x] Define acceptance criteria and VM validation obligations.
- [x] Review assumptions against the selected VM distribution and Podman version before implementation (initial 2026-11-03 VM deployment record).

## Phase 1 — Minimal executable foundation

- [x] Python project with pinned dependencies, lint/type checks and reproducible application image.
- [x] SQL schema + Alembic migrations for `sources`, `fetch_jobs`, `fetch_attempts`, `items`, `item_versions`.
- [x] Declarative source registry validator and deterministic source sync.
- [x] Database-backed scheduler, worker leases/retries and source-level rate limits.
- [x] FastAPI live/ready endpoints and read-only source/item endpoints.
- [x] Quadlet files for network, DB volume, PostgreSQL, API, singleton scheduler and worker, with host-local API binding and secrets.

**Phase 1 acceptance:** a fresh VM installation starts after reboot, persists database state across restart, rejects bad source config, keeps PostgreSQL unexposed and exposes a healthy loopback-only API. Demonstrate job idempotence and a successful backup restoration. Container build alone is not acceptance.

## Phase 2 — Actual end-to-end ingestion

- [x] RSS/Atom adapter and HTTP JSON API adapter, with conditional GET where supported.
- [ ] Official vulnerability/advisory feed and a second independently maintained public feed as first approved sources. Review their terms, rate limits and allowable stored fields before enabling.
- [x] Item normalization, stable IDs, version hashes, source provenance, reporting of unchanged updates.
- [x] Error classification and 429/backoff handling; source-level freshness view and change query.
- [x] Search indexes and documented API response schema.

**Phase 2 acceptance:** two actual approved sources ingest repeatedly into one schema; no duplicate items/versions on unchanged polls; publisher changes produce revisions; errors and provenance are visible. A third connector needs only an adapter + source registration, not another persistence stack.

## Phase 3 — Broader OSINT sources

- [x] Site-specific public HTML connector for selected official corporate recruiting pages, with policy review.
- [x] Additional security news, company IR/engineering blogs and release feeds.
- [ ] Explicit `stale/unknown/closed` state model and changes dashboard/report.
- [ ] Review search quality, polling costs, storage retention and indexing from measured usage.

**Phase 3 acceptance:** a corporate job source and a security feed are queryable side by side; job closure is not inferred from a transient missing page; no private career preferences are present in persisted data.

## Phase 4 — Knowledge enrichment (only if justified)

- [ ] Entity matching and evidence-backed relations across source categories.
- [ ] Optional summarization/enrichment with provenance, inference flags and reproducibility metadata.
- [ ] Consider graph/search extensions only if PostgreSQL quality/performance measurements show a real need.

Implementation checkboxes above mean the component exists in main, **not** that every production acceptance scenario was exercised. The approved-source activation, real repeated polling, browser UX, backup restore, and owner-authenticated report generation remain separate acceptance checks. The report subsystem is governed by [AUTOMATED_INTELLIGENCE_REPORTS.md](AUTOMATED_INTELLIGENCE_REPORTS.md); its VM/Codex verification remains NOT_CHECKED. Phase 4 is intentionally deferred.

## Minimum verification matrix

| Layer | Required evidence |
| --- | --- |
| Config | valid/invalid source YAML and duplicate IDs tested |
| Network | blocked loopback/private/link-local/metadata IPs, redirects and unsafe schemes |
| HTTP | 200/304/404/429/5xx, timeout, oversized response, conditional fetch |
| Workers | concurrent claim, crash + lease expiry, rate limiting, bounded retries |
| SQL | stable identity, duplicate fetch, changed version, transaction rollback, migration |
| API | actual JSON schema/pagination/search and no secret/full-body leakage |
| Container | built image, rootless Quadlet generator output, lifecycle and restart |
| Persistence | PostgreSQL volume survives rebuild/reboot; test backup restore |
| Compliance | source policy/terms/robots reviewed; public export metadata-only by default |

## Change management

- Implementation follows the narrowest phase required by the current acceptance condition; no unrelated framework or broker additions.
- Each PR/commit explains scope and tested evidence; CI completion is not a substitute for a VM runtime check.
- No installation onto a production VM, credentials, deployment, or public API exposure is implied by these design documents.
