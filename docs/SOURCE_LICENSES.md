# Official source rights and licensing

Reviewed: **2026-11-04**. These declarations distinguish **Nous's MIT-licensed
software** from information published by third parties. MIT grants no rights to
copy, relicense or resell publisher content, job listings, advisories or images.

## Catalog rights contract

Each `SourceConfig.policy` carries:

- `license_id`: a source-content SPDX identifier **only where established**;
  `NOASSERTION` means *no single verified reuse license has been established*,
  **not** public domain, CC0, MIT, or permission to republish.
- `license_url`: license/rights policy actually associated with the publisher;
  an informational policy link alone does not create a license grant.
- `terms_url`: publisher/feed access or service terms when identified.
- `attribution`: source-of-record for titles and links.
- `content_storage: metadata_only`: Nous stores title, identifiers, timestamp
  and source URL only; HTML descriptions, feeds' full bodies and images must
  not be mirrored. Respect robots instructions and source rate limits.

Existing source definitions without an explicit `license_id` resolve to
`NOASSERTION` through the schema default. Publisher-specific license status
must be verified before enabling or externally redistributing content.
Copyright and related rights are jurisdiction-sensitive; the Notes below are
technical collection constraints, **not** a legal opinion.

## New entries in this change

| Catalog ID | Publisher feed or board | Rights information | Status |
| --- | --- | --- | --- |
| `debian-security-advisories` | [Debian Security DSA RSS](https://www.debian.org/security/) | [Debian WWW license](https://www.debian.org/license): newer material MIT or GPL, older material under OPL; no uniform grant inferred for advisories | Disabled, probe pending |
| `debian-lts-advisories` | [Debian LTS DLA RSS](https://www.debian.org/lts/security/) | Same mixed-age Debian WWW terms; NOASSERTION for the entire feed | Disabled, probe pending |
| `ubuntu-security-notices` | [Ubuntu USN RSS](https://ubuntu.com/security/notices) | [Canonical website terms](https://ubuntu.com/legal/terms): not a general open-data license | Disabled, probe pending |
| `aws-security-bulletins` | [AWS Security Bulletins RSS](https://aws.amazon.com/security/security-bulletins/) | [AWS Terms](https://aws.amazon.com/terms/); publisher RSS contains approximately 30 days of items | Disabled, probe pending |
| `gitlab-patch-releases` | [GitLab release feeds](https://docs.gitlab.com/releases/) | RSS feed-specific reuse terms not established. Includes non-security patch releases; NOASSERTION | Disabled, probe pending |
| `google-cloud-security-bulletins` | [Google Cloud Security Bulletins](https://docs.cloud.google.com/support/bulletins) | XML link on official Google Cloud support page; no general feed republishing license established | Disabled, probe pending |
| `cloudflare-security-research` | [Cloudflare Security RSS](https://blog.cloudflare.com/tag/security/) | [Cloudflare terms](https://www.cloudflare.com/terms/); no license to mirror blog posts asserted | Disabled, probe pending |
| `fortinet-psirt` | [Fortinet PSIRT RSS](https://fortiguard.fortinet.com/psirt_policy) | Provider's PSIRT policy references the feed, but RSS reachability and content reuse rights remain unproven | Disabled, probe pending |
| `sie-japan-careers` | [SIE Japan jobs](https://job-boards.greenhouse.io/siei) | [Greenhouse public Job Board API](https://docs.greenhouse.io/job-board) allows unauthenticated GET, **not** a blanket redistribution license. Original job postings remain publisher-owned | Disabled, probe and categorization pending |

These are **catalog candidates**, not approved or enabled ingestion. The
official publisher pages or documented endpoints were inspected, but this
change did **not** execute the production `probe-source.yml` against all nine
endpoints. In particular, the Fortinet feed and SIE's API endpoint were not
independently confirmed to return a parseable successful response from Nous's
network environment.

## Existing bundled definitions

These continue unchanged. They are **not automatically relicensed** by the
new schema: `cisa-advisories`, `github-advisories`, `jpcert-alerts`,
`jpcert-notices`, `jvn-ipedia-updates`, `cloudflare-jobs`,
`meta-engineering`, and `automattic-jobs`. Their absent `license_id`
means `NOASSERTION` until an upstream rights review updates the declaration.

## Activation gate

1. Run `python -m nous.onboard_source --check-registry` for schema/ID checks.
2. Run the official `Probe a reviewed OSINT source` workflow for each source
   ID on the proposed ref; verify HTTP status, content-type, parse count,
   stable source URL and HTTPS item URLs.
3. Verify actual publisher terms/robots and whether metadata-only **internal
   use** is allowed; record relevant use restrictions, attribution and
   changes in publisher policies. Do not equate API availability with reuse
   permission or website terms with an SPDX license.
4. Activate only the explicitly reviewed source in the private Admin UI.
   Do not automatically activate new catalogs after image upgrades.
5. Measure first scheduled fetch and source history in the live instance.
   For job boards, a generic feed is not a validated `Japan/security` feed:
   add typed location/role filtering before enabling a focused job stream.

License notices for third-party **software dependencies** are a separate
distribution compliance question; their licenses do not govern publisher
data. Avoid copying third-party articles or descriptions into Nous's MIT
repository or GHCR image.
