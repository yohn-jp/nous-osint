# Contributing to Nous OSINT

Contributions are welcome when they preserve the project's source-first,
reproducible, metadata-focused collection model.

## Before making changes

Read [Architecture](docs/ARCHITECTURE.md),
[Data Contracts](docs/DATA_MODEL.md),
[Operations](docs/OPERATIONS.md), and [Security Policy](SECURITY.md).
Use a branch and a focused pull request. Explain the intended behavior, scope,
risk, and validation; do not push unreviewed changes to `main`.

## Development and verification

The project uses Python 3.12+, Node.js 24, Quasar, PostgreSQL, and Podman.
Follow the pinned dependency manifests and existing CI.

```sh
python -m pip install -e '.[dev]'
ruff check src migrations tests
python -m nous.onboard_source --check-registry
pytest -q
cd ui
npm ci
npm run typecheck
npm run build
```

Database-dependent tests require the PostgreSQL configuration and migrations
used by the CI workflow. Do not report them as passing if they were not run.
CI validates the unified container image on pull requests without publishing;
a `main` build publishes to GHCR. Image publication is not VM deployment.

## New information sources

Official catalog source definitions belong in `sources/*.yaml`. Use the Git proposal
UI or `python -m nous.onboard_source` to generate a **disabled** official candidate,
then submit a PR. For private, instance-local additions use the Admin UI and
PostgreSQL (see `docs/SOURCE_MANAGEMENT.md`); do not commit them to Git. Review the publisher's terms, robots guidance, metadata
storage permission, polling budget, extraction mapping, and provenance.

For supported sources, use the manually triggered source-probe workflow to
validate a bounded fetch. A successful probe does not establish legal permission
or automatically enable a source. Enable it only after review. Never add
secrets, private endpoints, personal recruitment information, or republished
third-party article bodies to the repository.

## Pull requests

Keep diffs limited to the requested change. Preserve the canonical registry,
database schema and origin authorization model. Include:

- What changed and why, including any data migration or security implications.
- Which checks ran, their actual results, and which checks remain unverified.
- For UI changes, the user flow affected and any browser/runtime limitations.
- For deployment changes, the expected image digest, rollback plan and
  distinction between CI success and live rollout.

Do not introduce a second source of truth or disable an existing security
boundary to make tests pass. Report vulnerabilities privately under
[SECURITY.md](SECURITY.md).
