# Correlated OSINT: evidence model and incremental implementation

Status: architecture analysis and implementation contract for the **FIRST EPSS observation slice**.
This document does not assert that the later features or new external feeds are deployed.

## Current system and the gap

Nous already has (a) source-defined, rate-limited collection; (b) immutable ItemVersion
observations and exact CVE references; (c) CISA KEV catalog membership observations
with three-valued freshness semantics; (d) approved, bounded report templates and
immutable evidence snapshots; (e) the private Astro release and operator gateway.
PR #44 separately adds source taxonomy and selectable report scope; keep its merge
state and deployment independent of this change.

A valid vulnerability intelligence workbench needs **independent evidence axes**
rather than one "risk" number:

| Axis | Truth condition | Safe interpretation |
|---|---|---|
| CVE identity | Strict `CVE-YYYY-NNNN` matching | A normalized identifier, not proof of exposure |
| FIRST EPSS | Official score/percentile and model date | Forward-looking 30-day exploitation-observation probability, not CVSS severity |
| Public PoC | Repo/commit/path and explicit CVE match | Candidate proof-of-concept reference, not working exploit validation |
| Nuclei template | Explicit template CVE identifier and signed provenance | Scannable template exists, not evidence of active exploitation |
| Scanning telemetry | Licensed provider's time-bounded observation | Vendor-specific observation, never implied by PoC or template |
| CISA KEV | Complete, recent authoritative catalog as-of | Confirmed historical exploitation catalog entry, not a current incident timestamp |
| Local impact | Verified asset/affected-version context | Unknown until supplied; no automatic impact inference |

FIRST explicitly warns against multiplying EPSS by the ordinal CVSS base score to
derive a purported calibrated probability: https://www.first.org/epss/faq .
The proposed weighted Threat Velocity formula is **research-only**, not a production
ranking, probability, compliance result or publication claim.

## Implemented first vertical slice (EPSS)

The scheduler queries FIRST's documented `GET /data/v1/epss?cve=...` API **only
for CVEs already tracked** by the canonical CVE link table. FIRST specifies that
its API is for small lookups, while bulk historical synchronization should use
its daily CSV archive: https://www.first.org/epss/data .

- Each check is bounded (90 CVEs per tick; query length capped at 1,750 CVE
  characters) and fetches only the official static host via the existing HTTPS
  transport's DNS/SSRF protections and response-size limit.
- The local EPSS table is append-only, keyed by exact CVE and UTC check date,
  with the official score date, decimal probability and percentile. A missing
  score is explicitly recorded as absence of an API result, **not zero**.
- A singleton poll state serializes refresh, bounds retries, and persists
  last success/failure without exposing provider body text or user credentials.
- At most 5,000 distinct currently linked CVEs are considered by this first
  bounded poller; this is not a complete national/global CVE mirror. Backlog
  follows the oldest previously queried CVEs, with a 15-minute interval;
  exhausted batches poll daily.
- The `/v1/cves/{id}` read model and MCP's existing `get_cve` expose a
  **read-only** EPSS value with source, score date, observation time and
  current/stale/not-scored/unknown status. KEV and CVE relation semantics
  remain independent. The report generator does not silently adopt the new
  metric as a verified claim.
- The runtime/image, migration and role grants must all reach the VM. A
  successful GitHub image build alone does not enable collection.

## Phase 2a: passive public CVE index snapshots (stacked PR)

This phase adds **repository index observations**, not downloaded or executed
proof-of-concept code. The two configured public sources are:

- `trickest/cve`: a generated CVE-year Markdown reference index. Many indexed pages explicitly
  say that no GitHub PoCs were found. A file name establishes only that Trickest
  has a CVE page, **not even that a PoC link exists**, let alone that one works,
  is safe, or represents exploitation in the wild.
- `projectdiscovery/nuclei-templates`: specifically `http/cves/<year>/`
  YAML template *path and Git blob hash* metadata. Other Nuclei protocols are
  explicitly outside this observation. A template is not a validated exploit
  or proof of a successful attack.

The metadata poller is anchored to the reviewed repository's main branch
commit, follows only hash-addressed, **nonrecursive** Git trees, validates
`truncated=false`, and rejects malformed entries or oversized directories.
It never requests file bodies. Filenames are matched to exact CVE identities,
and URLs use the immutable commit SHA rather than a mutable main-branch link.

GitHub's actual current public tree endpoints were inspected independently
of the production runtime: as of 2026-11-07, Trickest's 2026 directory
contained **18,767 CVE Markdown files** and Nuclei HTTP's 2026 directory
contained **532 YAML templates**, both with `truncated=false`. A sample
Trickest Markdown page explicitly stated "No PoCs found on GitHub currently,"
which is why **Trickest file presence is not a PoC detection signal**.
These were API contract probes; they do not establish that the VM has already
collected any data.

Each successful provider/year scan stores a content-addressed **PostgreSQL
JSONB** mapping of CVE→public file paths and blob hashes. The read model uses
JSONB key extraction for a single CVE; it must not transfer the 18k-entry
year index on each page request. It appends one observation with Git
commit SHA and **post-fetch** observation time. A missing entry means only
"not indexed within that complete repository/year scope." Missing, failed,
partial or older-than-72h observations are not reported as fresh absence.
Versions are never overwritten on disappearance or rename.

The canonical scheduler cycles one provider/year per tick across at most
16 tracked CVE publication years; existing DB-backed CVE identifiers determine
the targets. A dedicated, transaction-locked PostgreSQL singleton enforces at
least **15 minutes between all GitHub repository scan claims globally**,
including initial backlog and after errors, so 16 historical years do not
immediately burst the unauthenticated GitHub API limit. It does not issue external probes, clone repositories, run Nuclei,
download exploit code, or treat a GitHub index as CISA KEV.

`/v1/cves/{cve_id}`, the existing read-only MCP `get_cve` tool and the
CVE dossier surface these two independent metadata grades alongside
FIRST EPSS and official KEV status. No unreviewed severity/weaponization
score is inferred. No automatic report trigger is connected to this index yet.

### Release and acceptance

This PR is **stacked on PR #45** and does not imply it has been merged.
An actual release requires DB migration 0013, runtime/app image rollout, a
successful public-GitHub API lookup, persisted observations, source-date and
as-of UI validation, and least-privilege permission verification.
GitHub's unauthenticated API is rate limited, so each provider/year gets a
bounded per-day lookup with two-hour error backoff. Tests mock fixed GitHub
responses and do not prove actual production reachability.

## Later work in the supplied research concept (not implemented here)

**PoC correlation:** Track explicit CVE-to-commit and template identifiers with
source, first-seen time and immutable revisions. Do not clone/run arbitrary
exploit code or auto-scan targets. Nuclei's official project is
https://github.com/projectdiscovery/nuclei-templates and Trickest's is
https://github.com/trickest/cve . Claim categories must distinguish "a PoC
reference was indexed" from "technical exploitability was verified." A title
mention is not a trusted correlation. Avoid the ambiguous "Level 0: no PoC"
unless all coverage limitations are exposed.

**Regulatory disclosures and companies:** SEC Item 1.05 deadlines follow
**materiality determination**, not the initial event; reviewed filings are
necessary before labeling an incident. Official rules:
https://www.sec.gov/resources-small-businesses/small-business-compliance-guides/cybersecurity-risk-management-strategy-governance-incident-disclosure .
Use actual issuer CIK and filing accession, preserve the 8-K/8-K/A sequence,
and distinguish Item 1.05 from Item 5.02. The SEC requires identified
User-Agent and fair access:
https://www.sec.gov/search-filings/edgar-search-assistance/accessing-edgar-data .
Do not embed the illustrative contact email from the proposal. HHS/AG feeds
require format, access-terms and retention review before ingestion. Corporate
name matches alone are insufficient for identity. A nearby hiring event
cannot establish causation or identify a threat actor.

**Private investigation pivots:** Start with authenticated, explicitly scoped,
read-only source lookups and a bounded durable worklist. Independent confirmation
is required before producing a causal company timeline. Do not initiate
active probing, third-party IP enumeration or ransomware-site access merely
because an LLM proposed it. Gate acquisition rights, target scope, traffic
limits and escalation policy separately. Preserve exact evidence identifiers,
source time, hypothesis status and human review before publication.

## Implementation progression and proof

1. EPSS observations: deterministic parser and provenance; retention and as-of
   reading; daily bounded poll; API, MCP and UI. **This PR.**
2. Passive PoC index / Nuclei HTTP template metadata, with immutable year
   snapshots and as-of read paths. **This stacked PR.** Expanding protocols and
   alert-to-report triggers still requires separate review.
3. Issuer/filing identities and reviewed disclosure readers; cross-domain
   timeline distinguishes co-occurrence from causal inference. **Not yet
   implemented.**
4. Rules-based investigations and alert-to-report triggers only after
   event semantics, idempotency and publishing acceptance have been reviewed.
   **Not yet implemented.**

Operational acceptance for phase 1 requires successful migration and grants,
worker image availability *and application*, an actual FIRST lookup, persisted
daily observations, source-freshness UI, a second idempotent poll, and prior KEV
tests. Unit/CI fixtures prove software contracts, not an actual deployment.
