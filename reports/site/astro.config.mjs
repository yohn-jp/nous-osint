import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://nous.yohn.jp',
  base: '/reports/',
  output: 'static',
  trailingSlash: 'always',
  build: {
    format: 'directory',
    assets: '_astro',
  },
});
