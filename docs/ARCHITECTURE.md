# Nous OSINT — System Architecture

Status: **approved implementation baseline (design only)**  
Target: **single Linux VM / rootless Podman / systemd Quadlet / PostgreSQL**  
Updated: 2026-11-03

## 1. Purpose and scope

Nous OSINT is a general-purpose public-information ingestion and retrieval system. The first use cases are public job postings and company intelligence, security news, official advisories and vulnerability records. A source category must not require a separate scheduler, storage engine or deployment stack.

### In scope

- Declarative source registration; RSS/Atom, JSON API and public HTML connectors.
- Scheduled collection, conditional requests, bounded concurrency, retry and rate limiting.
- Normalization into source-linked records, canonical identifiers, deduplication and historical revisions.
- Structured provenance, text search, change detection, retrieval API and operational observability.
- Optional later-stage entity resolution and cross-source relationships.
- Reproducible deployment of the compute and SQL workloads on one VM.

### Out of scope for initial implementation

- Private job offers, resumes, personal recruiter correspondence or personally tailored suitability scores.
- Login bypass, paywall avoidance, anti-bot circumvention, intrusive scanning or collection from access-controlled sources without authorization.
- A full CTI/STIX/TAXII platform, automated judgments presented as facts, real-time internet-wide crawling.
- Multi-node high availability, a public web UI, vector search or automatic deployment of unreviewed models.
- Copying complete third-party articles into the public repository.

## 2. Runtime components

```text
Packaged official source catalog (YAML) + instance custom sources (SQL)
               |
               v
      Scheduler (one instance)
               | inserts due jobs idempotently
               v
    PostgreSQL job/outbox tables <-----------------+
               |                                  |
               v                                  |
       Worker(s) / adapters                       |
      RSS | JSON API | HTML                       |
               |                                  |
     safe fetch / extract / normalize             |
               |                                  |
               v                                  |
      items + immutable versions ------------------+
               |
               +--> read-only search API (FastAPI)
               +--> change reports / future enrichment
```

Use one application image with distinct commands for **scheduler**, **worker** and **API**; a separate official PostgreSQL image. One dedicated rootless OS account owns all Podman resources. The scheduler is a singleton; workers may be scaled locally. PostgreSQL is the only required coordination system. No message broker is introduced for the MVP.

### Component boundaries

- **Source management**: Git-tracked YAML is authoritative for the **official catalog**. Instance-specific enabled state and polling budgets override official defaults in SQL. Custom source declarations are owned by PostgreSQL and are never reset by catalog synchronization. The separate admin gateway requires verified Cloudflare Access identity, a subject allowlist and a dedicated DB role; Remote MCP and public query routes remain read-only. See [Source Management](SOURCE_MANAGEMENT.md).
- **Scheduler**: discovers due sources and creates durable jobs. A unique deduplication key makes repeated scheduler ticks harmless. Scheduler decisions are based on persisted state, not process memory.
- **Fetch worker**: claims a job using a short PostgreSQL transaction (`FOR UPDATE SKIP LOCKED` plus lease), releases that transaction before network I/O, then reports outcome transactionally. Workers are *at-least-once*, so all storage operations must be idempotent.
- **Adapters**: isolated code for RSS/Atom, JSON API and static HTML. Site-specific extraction is a separately versioned adapter/configuration, not a fork of the whole pipeline. JavaScript browser automation is deferred until a justified source requires it.
- **Normalizer**: applies type-specific validation without erasing source wording, stores source evidence and normalized attributes separately, and never substitutes an AI inference for source data.
- **Query API**: provides health, per-source status, item listing/search, version history and provenance. The authenticated gateway exposes a narrowly scoped admin API; public query endpoints and Remote MCP remain read-only.

## 3. Fetch and change pipeline

1. Validate source eligibility and configuration; resolve host and apply destination/IP policy.
2. Enforce per-domain limits, a descriptive User-Agent, connection/read timeout, total response-size limit and redirect limits.
3. Prefer official APIs and feeds. Use ETag/Last-Modified for conditional GET when supported.
4. Record each attempt: timestamp, outcome, HTTP status, final URL, policy decision, timings and error class.
5. Parse with bounded resource use. Canonicalize URLs conservatively; preserve meaningful parameters and publisher identifiers.
6. Normalize item fields and compute a stable content hash of the defined comparison payload.
7. If unchanged, update `last_seen_at` / retrieval metadata only. If changed, create an immutable item version and update the current pointer atomically.
8. Extract optional entities and relations **with attribution**, marking these as asserted facts or inferred candidates.
9. Schedule the next poll using source-specific cadence and backoff; publish observable counters.

A temporarily missing item does not automatically mean a vacancy is closed. Mark status as `unknown` or `stale` first; set `closed` only upon explicit publisher evidence or a documented connector-specific rule with a recorded basis.

### Failure and concurrency guarantees

- Retry network errors, 429 and selected 5xx with exponential backoff, bounded retries and `Retry-After` handling; permanent 4xx/policy violations fail without repeated hammering.
- Lease expiry returns abandoned jobs to the queue. At-least-once delivery + database uniqueness enforce effective idempotence.
- Enforce per-source and per-host concurrency ceilings across workers, not just in each process.
- Failed normalization does not delete previously valid versions; preserve diagnostic metadata without leaking secrets.
- Use bounded queue size/backpressure; a slow source must not block unrelated sources.

## 4. Trust, security and responsible collection

- **Public information is not automatically reusable content.** Retain allowed facts/metadata, source links and hashes; store full bodies only if terms and applicable rights permit, under explicit retention rules. Public exports must be independently reviewed.
- Respect source terms, robots directives where applicable, copyright, API quotas and explicit prohibitions. No credential stuffing, stealth browser profiles, CAPTCHA bypass or access-control evasion.
- Treat all retrieved text/HTML/JSON as **untrusted data**, not operating instructions. Never run embedded instructions, scripts or shell commands from sources.
- Prevent SSRF: enforce `http/https`, deny loopback, private, link-local, multicast and metadata-service addresses at DNS resolution and after every redirect; bound redirects and payload sizes. Prevent unsafe file/URL schemes.
- Prevent SQL injection with parameterized queries; escape/sanitize HTML before display.
- No exposed PostgreSQL port; API binds only to loopback or an explicitly authenticated private reverse proxy.
- Run containers rootless with least privileges, resource limits and no host Podman socket mounted into application containers.
- Secrets stay in VM-managed secret storage; never commit credentials, DSNs with passwords, private data or operational dumps.
- If later adding LLM-based extraction, store model ID, prompt/version, evidence range, output confidence and validation status; never silently promote inferred assertions into verified facts.

## 5. Search and extension model

MVP: PostgreSQL native indexes, `tsvector`/GIN full-text search and structured filters (type, source, organization, publication/retrieval time, current/stale state). JSONB is permitted for source-specific attributes, but primary filters must be typed columns.

Later phases may add entity linking across jobs, companies, CVEs, products and advisories. Relations must include a supporting source or be explicitly identified as hypotheses. Do not add graph databases, embeddings or external search engines until demonstrated query volume/quality requires them.

## 6. Observability and operation

Collect structured logs (with URL credentials stripped), source poll lag, successful/failed attempts, 429 counts, parse failures, queue age/depth, stale leases, DB/storage growth, API latency and last-success timestamps. Readiness probes must verify actual database access; liveness must not depend on an external publisher.

Set per-source failure thresholds and report degraded sources individually rather than labeling the entire service healthy. Publish periodic status and change summaries from persisted data rather than relying on ephemeral process memory.

## 7. Decisions and authority

- **ADR-001**: One VM + rootless Podman + Quadlet; no Docker Compose/Kubernetes for the first deployment.
- **ADR-002**: PostgreSQL is runtime record and job-state authority; Git is source/configuration authority.
- **ADR-003**: Separate immutable source observations from normalized facts and inferred links.
- **ADR-004**: Collection is code-driven and deterministic; AI enrichment is optional and downstream.
- **ADR-005**: The public repository contains implementation and configuration only, not unrestricted third-party content.
- **ADR-006**: PostgreSQL version and container digest are explicitly pinned during implementation; upgrades are deliberate migrations with backup/restore validation.

See [DATA_MODEL.md](DATA_MODEL.md), [QUADLET_DEPLOYMENT.md](QUADLET_DEPLOYMENT.md), and [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## CVE identity and KEV evidence

The PostgreSQL `cve_item_links` index (Alembic 0007) joins canonical CVE IDs to source-backed observations without merging or rewriting their item versions. CISA KEV (`cisa_kev_v1`) is the sole authoritative exploitation assertion; other source references remain evidence-graded mentions/records. Read via `/v1/cves/{cve_id}` or MCP `get_cve`. Missing/stale KEV data is not interpreted as absence of exploitation. See [CVE/KEV contract](CVE_KEV_CORRELATION.md).
