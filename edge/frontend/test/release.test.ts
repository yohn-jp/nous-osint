import { test } from 'node:test';
import assert from 'node:assert/strict';
import { release } from '../scripts/release.mjs';

const options = { sha: 'a'.repeat(40), mode: 'production', accountId: 'b'.repeat(32), zoneId: 'c'.repeat(32), token: 'synthetic-cf', githubToken: 'synthetic-github', repository: 'owner/repo' };
const version = '12345678-1234-1234-1234-123456789012';
function fixture({ staleAt = 0, publicURL = false, badArtifact = false, missingWorker = false,
  badUpload = false, missingVersion = false, duplicateVersion = false, wrongVersionTag = false,
  versionListForbidden = false, oldTaggedVersion = false, badAssetFallback = false } = {}) {
  const commands: string[][] = [];
  let headChecks = 0;
  return { commands, dependencies: {
    load: async (url: URL) => JSON.stringify(url.pathname.endsWith('provenance.json') ? { sha: badArtifact ? 'd'.repeat(40) : options.sha, mode: options.mode }
      : url.pathname.endsWith('worker.config.json') ? { name: 'nous-frontend', workersDev: false, previewUrls: false, env: {}, assets: { runWorkerFirst: false, notFoundHandling: badAssetFallback ? 'single-page-application' : 'none' } }
      : { buildContext: { isPreview: false, mode: options.mode } }),
    apiFetch: async (url: string) => {
      assert(url.startsWith('https://api.github.com/') || url.startsWith('https://api.cloudflare.com/'));
      if (url.includes('api.github.com')) return new Response(JSON.stringify({ object: { sha: ++headChecks === staleAt ? 'd'.repeat(40) : options.sha } }));
      if (url.includes('/workers/scripts/nous-frontend/versions?')) {
        if (versionListForbidden) return new Response('', { status: 403 });
        const uploaded = commands.some(command => command[1] === 'versions');
        const old = oldTaggedVersion ? [{ id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', annotations: { 'workers/tag': options.sha } }] : [];
        const created = uploaded && !missingVersion ? [{ id: version, annotations: { 'workers/tag': wrongVersionTag ? 'd'.repeat(40) : options.sha } }] : [];
        if (duplicateVersion && created.length) created.push({ ...created[0], id: 'cccccccc-cccc-cccc-cccc-cccccccccccc' });
        const items = [...old, ...created];
        return new Response(JSON.stringify({ success: true, result: { items }, result_info: { total_count: items.length } }));
      }
      assert(url.endsWith('/workers/scripts/nous-frontend/subdomain'));
      return new Response(JSON.stringify({ success: true, result: { enabled: publicURL, previews_enabled: publicURL } }), { status: missingWorker ? 404 : 200 });
    },
    run: (args: string[]) => { commands.push(args); if (badUpload && args[1] === 'versions') throw new Error('cf upload failed'); return 'CLI output changed without a version marker'; },
  } };
}

test('release finds newly tagged Worker Version through API despite changed CLI output', async () => {
  const f = fixture();
  const result = await release(options, f.dependencies);
  assert.equal(result.version, version);
  assert.equal(f.commands.length, 2);
  assert.deepEqual(f.commands[0].slice(0, 3), ['workers', 'versions', 'create']);
  assert.deepEqual(f.commands[1].slice(0, 3), ['workers', 'deployments', 'create']);
  assert.equal(f.commands[0][f.commands[0].indexOf('--tag') + 1], options.sha);
  assert.deepEqual(JSON.parse(f.commands[1].at(-1)!), [{ version_id: version, percentage: 100 }]);
});

test('stale commits, public endpoints, missing Worker and wrong artifacts cannot activate', async () => {
  for (const config of [{ staleAt: 1 }, { staleAt: 2 }, { publicURL: true }, { missingWorker: true },
    { badArtifact: true }, { badUpload: true }, { missingVersion: true },
    { duplicateVersion: true }, { wrongVersionTag: true }, { versionListForbidden: true },
    { badAssetFallback: true }]) {
    const f = fixture(config);
    await assert.rejects(release(options, f.dependencies));
    assert(!f.commands.some(command => command[1] === 'deployments'));
  }
});

test('obsolete origin-passthrough release mode is forbidden', async () => {
  const f = fixture();
  await assert.rejects(release({ ...options, mode: 'passthrough' }, f.dependencies));
  assert.equal(f.commands.length, 0);
});

test('an older version with the same SHA is never mistaken for the new upload', async () => {
  const f = fixture({ oldTaggedVersion: true });
  const result = await release(options, f.dependencies);
  assert.equal(result.version, version);
  assert.deepEqual(JSON.parse(f.commands[1].at(-1)!), [{ version_id: version, percentage: 100 }]);
});
