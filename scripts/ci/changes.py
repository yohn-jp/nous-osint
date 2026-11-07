#!/usr/bin/env python3
"""Classify the complete push/PR diff; deletions and renamed paths are included."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
from urllib.request import Request, urlopen

SCOPES = ('python', 'frontend', 'backend_image', 'reports', 'report_image', 'terraform')
REPORT_MODULES = {
    'src/nous/report_worker.py', 'src/nous/report_pipeline.py',
    'src/nous/report_editorial.py', 'src/nous/report_diagnostics.py',
    'src/nous/report_templates.py', 'src/nous/cve_index.py',
    'src/nous/cve_queries.py', 'src/nous/db.py', 'src/nous/models.py',
    'src/nous/registry.py', 'src/nous/source_taxonomy.py',
    'src/nous/social_feeds.py', 'src/nous/epss.py', 'src/nous/public_artifacts.py',
    'src/nous/fetch.py', 'src/nous/__init__.py',
}


def classify(paths: list[str]) -> dict[str, bool]:
    result = dict.fromkeys(SCOPES, False)
    for path in paths:
        if (path.startswith(('docs/', '.github/ISSUE_TEMPLATE/'))
                or ('/' not in path and path.endswith('.md'))
                or path.rsplit('/', 1)[-1] == 'README.md'):
            continue
        if path.startswith(('ui/', 'edge/frontend/')):
            result['frontend'] = True
        elif path.startswith('deploy/cloudflare/terraform/'):
            result['terraform'] = True
        elif path.startswith('reports/'):
            result.update(python=True, reports=True, report_image=True)
            if path.startswith('reports/templates/'):
                result['backend_image'] = True
        elif path.startswith('src/'):
            result['python'] = True
            if path not in {'src/nous/report_worker.py', 'src/nous/report_pipeline.py'}:
                result['backend_image'] = True
            if path in REPORT_MODULES or not path.startswith('src/nous/'):
                result.update(reports=True, report_image=True)
            if path == 'src/nous/access_auth.py':
                result['frontend'] = True  # Python/Edge routing parity test.
        elif path.startswith(('migrations/', 'sources/')) or path in {'pyproject.toml', 'alembic.ini'}:
            result.update(python=True, backend_image=True, reports=True, report_image=True)
        elif path == 'Containerfile':
            result.update(python=True, backend_image=True)
        elif path == 'Containerfile.reports':
            result.update(python=True, reports=True, report_image=True)
        elif path.startswith('tests/'):
            result['python'] = True
        elif path.startswith(('scripts/ci/', '.github/workflows/')):
            # Shared CI contracts must exercise every lane when modified.
            result = dict.fromkeys(SCOPES, True)
        elif path.startswith(('scripts/', 'deploy/')):
            result['python'] = True
        elif path in {'.gitignore', 'LICENSE', 'CODE_OF_CONDUCT', 'SECURITY'}:
            continue
        else:
            # New/unclassified build inputs fail conservatively; no truncated
            # GitHub changed-file API or path-filter length limits.
            result = dict.fromkeys(SCOPES, True)
    return result


def git(*args: str) -> str:
    return subprocess.check_output(['git', *args], text=True)


def revision(value: str) -> str:
    if not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ValueError('Expected a full Git SHA')
    try:
        git('cat-file', '-e', value + '^{commit}')
    except subprocess.CalledProcessError:
        subprocess.run(['git', 'fetch', '--no-tags', 'origin', value], check=True)
    return value


def changed_paths(event: dict, event_name: str, checkpoint: str | None = None) -> list[str]:
    if event_name == 'pull_request':
        base = revision(event['pull_request']['base']['sha'])
        head = revision(event['pull_request']['head']['sha'])
        base = git('merge-base', base, head).strip()
    elif event_name == 'push':
        head = revision(event['after'])
        if event['before'] == '0' * 40:
            return git('ls-tree', '-r', '--name-only', '-z', head).split('\0')[:-1]
        base = revision(event['before'])
    else:
        raise ValueError(f'Unsupported event: {event_name}')
    paths = git('diff', '--no-renames', '--name-only', '-z', base, head).split('\0')[:-1]
    if event_name == 'push' and checkpoint is not None:
        if checkpoint == '0' * 40:
            return git('ls-tree', '-r', '--name-only', '-z', head).split('\0')[:-1]
        checkpoint = revision(checkpoint)
        paths += git('diff', '--no-renames', '--name-only', '-z', checkpoint, head).split('\0')[:-1]
    return sorted(set(paths))


def successful_main() -> str:
    # Carry forward unreleased changes after failed/superseded main runs. Without
    # this, an old UI release rejected as stale could be lost on a backend push.
    repository = os.environ['GITHUB_REPOSITORY']
    request = Request(
        f'https://api.github.com/repos/{repository}/actions/workflows/ci.yml/runs'
        '?branch=main&event=push&status=success&per_page=1',
        headers={'Authorization': f'Bearer {os.environ["GH_TOKEN"]}',
                 'Accept': 'application/vnd.github+json'},
    )
    with urlopen(request, timeout=30) as response:
        runs = json.load(response)['workflow_runs']
    return runs[0]['head_sha'] if runs else '0' * 40


if __name__ == '__main__':
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    name = os.environ['GITHUB_EVENT_NAME']
    checkpoint = successful_main() if name == 'push' else None
    scopes = classify(changed_paths(event, name, checkpoint))
    output = ''.join(f'{key}={str(value).lower()}\n' for key, value in scopes.items())
    print(output, end='')
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as target:
        target.write(output)
    if summary := os.getenv('GITHUB_STEP_SUMMARY'):
        with Path(summary).open('a') as target:
            target.write('Changed-file scopes:\n\n```text\n' + output + '```\n')
