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
2. Passive PoC / template metadata: separate structured evidence, safe indexing
   and before/after comparisons. **Not yet implemented.**
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
