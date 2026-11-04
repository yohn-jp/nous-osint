import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://nous.yohn.jp',
  base: '/reports/',
  output: 'static',
  // node_modules is mounted from the read-only Worker image during publishing.
  cacheDir: './.astro-cache',
  trailingSlash: 'always',
  build: {
    format: 'directory',
    assets: '_astro',
  },
});
