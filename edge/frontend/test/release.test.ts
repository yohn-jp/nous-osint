import { test } from 'node:test';
import assert from 'node:assert/strict';
import { release } from '../scripts/release.mjs';

const options = { sha: 'a'.repeat(40), mode: 'production', accountId: 'b'.repeat(32), zoneId: 'c'.repeat(32), token: 'synthetic-cf', githubToken: 'synthetic-github', repository: 'owner/repo' };
const version = '12345678-1234-1234-1234-123456789012';
function fixture({ staleAt = 0, publicURL = false, badArtifact = false, missingWorker = false, badUpload = false } = {}) {
  const commands: string[][] = [];
  let headChecks = 0;
  return { commands, dependencies: {
    load: async (url: URL) => JSON.stringify(url.pathname.endsWith('provenance.json') ? { sha: badArtifact ? 'd'.repeat(40) : options.sha, mode: options.mode }
      : url.pathname.endsWith('worker.config.json') ? { name: 'nous-frontend', workersDev: false, previewUrls: false, env: {}, assets: { runWorkerFirst: false, notFoundHandling: 'single-page-application' } }
      : { buildContext: { isPreview: false, mode: options.mode } }),
    apiFetch: async (url: string) => {
      assert(url.startsWith('https://api.github.com/') || url.startsWith('https://api.cloudflare.com/'));
      if (url.includes('api.github.com')) return new Response(JSON.stringify({ object: { sha: ++headChecks === staleAt ? 'd'.repeat(40) : options.sha } }));
      assert(url.endsWith('/workers/scripts/nous-frontend/subdomain'));
      return new Response(JSON.stringify({ success: true, result: { enabled: publicURL, previews_enabled: publicURL } }), { status: missingWorker ? 404 : 200 });
    },
    run: (args: string[]) => { commands.push(args); return badUpload ? 'ambiguous output' : `Worker Version ID: ${version}`; },
  } };
}

test('release uploads exact artifact then activates that UUID without managing routes', async () => {
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
  for (const config of [{ staleAt: 1 }, { staleAt: 2 }, { publicURL: true }, { missingWorker: true }, { badArtifact: true }, { badUpload: true }]) {
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
