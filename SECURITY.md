# Security Policy

## Supported versions

Nous OSINT is pre-1.0. Security fixes target the latest `main` revision and the
currently deployed release. Older releases and historical container digests are
not maintained as long-term-support branches. An architectural plan is not
evidence that a security control is deployed.

## Reporting a vulnerability

**Do not disclose vulnerabilities in public Issues or pull requests.**

Use [GitHub's private vulnerability reporting](../../security/advisories/new)
to report a security issue. If private reporting is not available, contact the
maintainers through a non-public channel before sharing exploit details.
Do not publish credentials, Cloudflare Access assertions, OAuth tokens, database
content, internal infrastructure addresses, or private OSINT records.

Useful reports identify the affected version/commit or image digest, impact,
prerequisites, and a minimal safe reproduction. Maintainers review reports on
a best-effort basis; no fixed response SLA is promised.

## Security boundaries

- **Authentication:** Cloudflare Access protects the browser UI and remote MCP.
  The origin independently validates the Access JWT; a tunnel alone is not
  an authentication boundary.
- **MCP and APIs:** Remote MCP and the application API are read-only. Git-based catalog proposals never grant MCP write access. The separate
  Admin UI/API may manage instance-local sources only when the signed Access
  subject is explicitly allowlisted and the dedicated DB role is provisioned.
- **Collector:** Sources must pass policy review before activation. The fetcher
  must reject private, loopback, link-local, and other forbidden destinations,
  including redirects and DNS rebinding scenarios. Rate limits and bounded
  extraction protect the VM and upstream publishers.
- **Storage:** PostgreSQL holds normalized records and provenance. Publisher
  content rights and storage scope must be respected; credentials and private
  user evaluations must not be committed to the public repository.
- **Caching:** Shared Cloudflare caching is restricted to identity-independent,
  versioned static assets. HTML, JSON APIs, OAuth/MCP and error responses must
  not be stored by shared caches. See [Cache Strategy](docs/CACHE_STRATEGY.md).
- **Deployment:** GitHub Actions publishes the app image to GHCR. Deployments
  must pin a verified immutable digest and preserve a rollback reference.
  Registry credentials remain on the VM, never in the browser or repository.

## Disclosure and verification

Avoid probing the production service, connected upstream publishers, or other
users' data without authorization. Coordinate potentially disruptive
reproduction privately. Security fixes require validation of the affected
boundary; passing CI alone does not certify the live VM, Access policy, or
Cloudflare cache behavior.
