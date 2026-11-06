import { readdir, readFile, mkdir, rm, copyFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

// Publish only the SPA entry and flat Quasar build assets, never arbitrary files,
// sourcemaps, dotfiles, _redirects, _headers or runtime-generated private reports.
const source = new URL('../../../ui/dist/spa/', import.meta.url);
const target = new URL('../public/', import.meta.url);
const index = await readFile(new URL('index.html', source), 'utf8');
assert(index.includes('/assets/'), 'Quasar output must contain absolute asset URLs');
await rm(target, { recursive: true, force: true });
await mkdir(new URL('assets/', target), { recursive: true });
await copyFile(new URL('index.html', source), new URL('index.html', target));
let count = 0;
for (const entry of await readdir(new URL('assets/', source), { withFileTypes: true })) {
  assert(entry.isFile(), `Unexpected nested/symlink asset: ${entry.name}`);
  assert(/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}$/.test(entry.name), `Invalid asset: ${entry.name}`);
  assert(!entry.name.endsWith('.map'), 'Do not publish source maps');
  await copyFile(new URL(`assets/${entry.name}`, source), new URL(`assets/${entry.name}`, target));
  count++;
}
assert(count > 0, 'Missing Quasar assets');
console.log(`Prepared index.html and ${count} Quasar assets`);
