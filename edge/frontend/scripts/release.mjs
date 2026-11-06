/** Upload static UI script/assets only: never deploy routes, DNS, Tunnel or Access. */
import assert from 'node:assert/strict';
import { readFile, appendFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

export async function release(options, { apiFetch = fetch, run = runCLI, load = readFile } = {}) {
  const { sha, mode, accountId, zoneId, token, githubToken, repository } = options;
  assert(/^[a-f0-9]{40}$/.test(sha), 'Expected immutable main SHA');
  assert.equal(mode, 'production', 'Only static UI production releases are allowed');
  assert(/^[a-f0-9]{32}$/.test(accountId || ''), 'Missing/invalid CLOUDFLARE_ACCOUNT_ID');
  assert(/^[a-f0-9]{32}$/.test(zoneId || ''), 'Missing/invalid CLOUDFLARE_ZONE_ID context');
  assert(token && githubToken && /^[\w.-]+\/[\w.-]+$/.test(repository), 'Missing release credentials/context');
  const root = new URL('../.cloudflare/output/v0/', import.meta.url);
  const build = JSON.parse(await load(new URL('config.json', root), 'utf8'));
  const worker = JSON.parse(await load(new URL('workers/default/worker.config.json', root), 'utf8'));
  const provenance = JSON.parse(await load(new URL('provenance.json', root), 'utf8'));
  assert.equal(provenance.sha, sha, 'Artifact SHA mismatch');
  assert.equal(provenance.mode, mode, 'Artifact mode mismatch');
  assert.equal(build.buildContext.isPreview, false);
  assert.equal(build.buildContext.mode, mode);
  assert.equal(worker.name, 'nous-frontend');
  assert.equal(worker.workersDev, false);
  assert.equal(worker.previewUrls, false);
  assert.equal(worker.domains, undefined);
  assert.equal(worker.triggers, undefined);
  assert.equal(worker.assets.runWorkerFirst, false, 'Static assets must bypass Worker script');
  assert.equal(worker.assets.notFoundHandling, 'single-page-application', 'SPA fallback must be served by assets runtime');
  assert.equal(worker.env.PASSTHROUGH_ONLY, undefined, 'Origin passthrough binding is forbidden');

  async function currentMain() {
    const response = await apiFetch(`https://api.github.com/repos/${repository}/git/ref/heads/main`, {
      headers: { Authorization: `Bearer ${githubToken}`, Accept: 'application/vnd.github+json' },
    });
    assert(response.ok, `Unable to check main HEAD (${response.status})`);
    assert.equal((await response.json()).object.sha, sha, 'Stale release refused: main advanced');
  }
  async function privateWorker() {
    const response = await apiFetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/nous-frontend/subdomain`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert(response.ok, `Private Worker preflight failed (${response.status}); bootstrap separately before enabling releases`);
    const body = await response.json();
    assert.equal(body.success, true);
    assert.equal(body.result.enabled, false, 'workers.dev must already be disabled');
    assert.equal(body.result.previews_enabled, false, 'Version previews must already be disabled');
  }
  // Cloudflare's version-list API is stable; the beta cf CLI's human-readable
  // stdout is not. Snapshot IDs before upload so a retry cannot accidentally
  // activate an earlier version carrying the same commit tag.
  async function workerVersions() {
    const versions = [];
    for (let page = 1; page <= 100; page++) {
      const response = await apiFetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/nous-frontend/versions?page=${page}&per_page=100`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      assert(response.ok, `Unable to list Worker versions (${response.status})`);
      const body = await response.json();
      assert.equal(body.success, true, 'Worker versions query unsuccessful');
      const items = body.result?.items;
      assert(Array.isArray(items), 'Malformed Worker versions response');
      versions.push(...items);
      const total = body.result_info?.total_count;
      if (items.length === 0 || (Number.isSafeInteger(total) && versions.length >= total) ||
          (total === undefined && items.length < 100)) return versions;
    }
    throw new Error('Worker versions pagination limit exceeded');
  }
  await currentMain();
  await privateWorker();
  const previousIds = new Set((await workerVersions()).map(version => version.id));
  run(['workers', 'versions', 'create', '--prebuilt', '--mode', mode,
    '--tag', sha, '--message', `GitHub ${repository}@${sha}`]);
  let uploaded = [];
  for (let attempt = 0; attempt < 4; attempt++) {
    uploaded = (await workerVersions()).filter(version =>
      !previousIds.has(version.id) && version.annotations?.['workers/tag'] === sha);
    assert(uploaded.length <= 1, 'Ambiguous newly uploaded Worker versions for this SHA');
    if (uploaded.length === 1) break;
    if (attempt < 3) await sleep(250 * (attempt + 1));
  }
  assert.equal(uploaded.length, 1, 'Expected one newly uploaded Worker Version tagged with main SHA');
  const id = uploaded[0].id;
  assert(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(id), 'Invalid Worker version ID');
  await privateWorker();
  await currentMain(); // Immediately before the only traffic-changing operation.
  run(['workers', 'deployments', 'create', '--worker', 'nous-frontend',
    '--strategy', 'percentage', '--versions', JSON.stringify([{ version_id: id, percentage: 100 }])]);
  return { sha, mode, version: id, zoneId };
}

function runCLI(args) {
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('../node_modules/cf/bin/cf', import.meta.url)), ...args], {
    cwd: fileURLToPath(new URL('..', import.meta.url)), encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1' },
  });
  // Do not echo CLI error bodies, environment or credentials into public logs.
  assert.equal(result.status, 0, `cf ${args.slice(0, 3).join(' ')} failed; activation stopped`);
  return result.stdout;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await release({ sha: process.env.GITHUB_SHA, mode: process.env.FRONTEND_RELEASE_MODE,
      accountId: process.env.CLOUDFLARE_ACCOUNT_ID, zoneId: process.env.CLOUDFLARE_ZONE_ID,
      token: process.env.CLOUDFLARE_API_TOKEN, githubToken: process.env.GITHUB_TOKEN,
      repository: process.env.GITHUB_REPOSITORY });
    console.log(JSON.stringify(result));
    if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY,
      `Edge release: ${result.sha}\n\nMode: ${result.mode}\n\nWorker version: ${result.version}\n`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
